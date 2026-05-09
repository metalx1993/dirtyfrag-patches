# Dirty Frag — Kernel Patches

Patch series for the **Dirty Frag** vulnerability class discovered by [Hyunwoo Kim (@v4bel)](https://github.com/V4bel/dirtyfrag).

Dirty Frag allows an unprivileged local user to overwrite arbitrary bytes of the page cache of read-only files (e.g. `/usr/bin/su`, `/etc/passwd`) leading to **local privilege escalation to root** on all major Linux distributions.

---

## Patches

| File | CVE | Subsystem | Status |
|---|---|---|---|
| [`0001-net-xfrm-fix-page-cache-write-via-esp-splice-CVE-2026-43284.patch`](./0001-net-xfrm-fix-page-cache-write-via-esp-splice-CVE-2026-43284.patch) | CVE-2026-43284 | `net/ipv4/esp4.c`, `net/ipv6/esp6.c`, `net/ipv4/ip_output.c`, `net/ipv6/ip6_output.c` | ✅ Merged in mainline ([`f4c50a4034e6`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4)) |
| [`0002-net-rxrpc-fix-page-cache-write-via-rxkad-splice-CVE-2026-43500.patch`](./0002-net-rxrpc-fix-page-cache-write-via-rxkad-splice-CVE-2026-43500.patch) | CVE-2026-43500 | `net/rxrpc/call_event.c`, `net/rxrpc/conn_event.c` | ⏳ Submitted to netdev ML ([`afKV2zGR6rrelPC7@v4bel`](https://lore.kernel.org/all/afKV2zGR6rrelPC7@v4bel/)), pending merge |

---

## Affected Kernel Versions

- **CVE-2026-43284** (ESP): kernels from `4.10` (commit `cac2661c53f3`, 2017-01-17) up to `6.x` pre-`f4c50a4034e6`
- **CVE-2026-43500** (RxRPC): kernels from `6.4` (commit `2dc334f1a63a`, 2023-06-08) up to upstream (no patch merged yet)

---

## How to Apply

### Apply to a kernel source tree

```bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux

# Apply patch 1 (ESP — CVE-2026-43284)
git am 0001-net-xfrm-fix-page-cache-write-via-esp-splice-CVE-2026-43284.patch

# Apply patch 2 (RxRPC — CVE-2026-43500)
git am 0002-net-rxrpc-fix-page-cache-write-via-rxkad-splice-CVE-2026-43500.patch
```

### Apply with `patch` (if git am fails due to context drift)

```bash
patch -p1 < 0001-net-xfrm-fix-page-cache-write-via-esp-splice-CVE-2026-43284.patch
patch -p1 < 0002-net-rxrpc-fix-page-cache-write-via-rxkad-splice-CVE-2026-43500.patch
```

---

## Immediate Mitigation (no kernel recompilation needed)

If you cannot apply the patch immediately, blacklist the vulnerable modules:

```bash
sudo sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
    > /etc/modprobe.d/dirtyfrag.conf && \
    rmmod esp4 esp6 rxrpc 2>/dev/null; \
    echo 3 > /proc/sys/vm/drop_caches"
```

> **Warning:** Removing `esp4`/`esp6` disables IPsec ESP. Evaluate the impact before applying on production systems.

---

## Technical Summary

### Root Cause

Both variants share the same root cause: the kernel's zero-copy `splice()` path plants a **read-only page-cache page** directly into an `skb` frag without copy-on-write semantics. Subsequent in-place crypto operations then write into that page-cache page, permanently modifying the cached file content.

```
splice(file_fd → pipe → socket)
         │
         ▼
  skb->frags[0].page = &page_cache_page_P   ← no CoW!
         │
         ▼
  [esp_input / rxkad_verify_packet_1]
  in-place AEAD/fcrypt decrypt  src == dst == &P
         │
         ▼
  STORE to page_cache_page_P     ← arbitrary write to read-only file cache
```

### Fix Strategy

| Variant | Approach |
|---|---|
| **ESP** | Mark splice frags with `SKBFL_SHARED_FRAG`; check this flag in `esp_input()`/`esp6_input()` to force `skb_cow_data()` before in-place crypto |
| **RxRPC** | Extend `skb_cloned()` gate to `(skb_cloned(skb) \|\| skb->data_len)` so non-linear skbs (which may contain splice frags) are always copied before in-place decryption |

---

## References

- Original PoC & write-up: https://github.com/V4bel/dirtyfrag
- CVE-2026-43284: https://www.cve.org/CVERecord?id=CVE-2026-43284
- CVE-2026-43500: https://www.cve.org/CVERecord?id=CVE-2026-43500
- Mainline commit (ESP fix): https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4
- RxRPC patch (netdev ML): https://lore.kernel.org/all/afKV2zGR6rrelPC7@v4bel/
- Copy Fail (ancestor vulnerability): https://copy.fail/
- Dirty Pipe (same bug class): https://dirtypipe.cm4all.com/
