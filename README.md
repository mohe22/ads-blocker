# ads-blocker
A lightweight DNS-based ad blocker written in C++ that intercepts and filters unwanted domains at the network level.

---

## Before & After

| Before | After |
|--------|-------|
| ![before](place) | ![after](place) |

---

## Features

- **DNS interception** — listens on UDP port 53 and intercepts all outgoing DNS queries before they reach the resolver
- **Full DNS packet parsing** — parses raw DNS wire format including headers, question/answer sections, and resource records
- **Parent-domain matching** — blocking `ads.com` automatically blocks all subdomains like `sub.ads.com`
- **URL normalization** — strips schema (`https://`), paths, and query strings before matching, so any raw URL format is handled correctly
- **Upstream forwarding** — unblocked queries are forwarded to a configurable upstream resolver (default: `8.8.8.8`) with a configurable timeout
- **Multiple blocklist files** — load as many blocklist files as needed at startup
- **Path shorthands** — convenient shortcuts like `desktop/`, `downloads/`, `~/` for pointing to blocklist files
---

## Build

```bash
g++ src/main.cpp src/server/server.cpp src/parser/parser.cpp --std=c++26 -lstdc++exp -lws2_32 -o dns
```

> Requires a C++26 compatible compiler (GCC 14+). The `-lws2_32` flag is Windows-specific (Winsock).

---

## How It Works

The blocker sits between your machine and the DNS resolver, intercepting every DNS query before it goes out.

When a domain is looked up, it first strips the schema (`https://`) and any path or query string, leaving just the bare domain like `google.com`. It then walks up the domain hierarchy — checking `sub.evil.com`, then `evil.com`, then `com` — against a blocklist stored in a trie. If any level matches, the query is blocked and no response is returned. If nothing matches, the query is forwarded normally.

This parent-domain matching means blocking `ads.com` automatically covers all subdomains under it.

---

## Usage

```bash
ads-blocker [OPTIONS] [BLOCKLIST_FILES...]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--ip <addr>` | Local IP to bind to | `0.0.0.0` |
| `--port <port>` | UDP port to listen on | `53` |
| `--upstream <addr>` | Upstream DNS resolver | `8.8.8.8` |
| `--timeout <ms>` | Upstream timeout in ms | `5000` |
| `--help` | Show help message | |

**Blocklist path shorthands:**

```
~/...            →  Home directory
desktop/...      →  ~/Desktop/
documents/...    →  ~/Documents/
downloads/...    →  ~/Downloads/
```

**Example:**

```bash
ads-blocker --upstream 1.1.1.1 desktop/ads.txt ~/lists/malware.txt
```

---

## In Depth

For a full deep dive into how the DNS interception, trie structure, and domain matching works, check out the [blog post](https://mohe-things.netlify.app/blogs/ad-blocker).
