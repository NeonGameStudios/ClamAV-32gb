# R03 current-host qualification preflight — 2026-09-14

Task ID / parent milestone: `R03` / `R05` / `R11`.

The current canonical host was checked with the roadmap's existing host
preflight command:

```text
sh tools/largefile_host_preflight.sh /tmp/clamav-host-preflight-current-20260914 50000000
```

It exited 1 before creating host evidence:

```text
host preflight requires Linux x86-64 (found Darwin/arm64)
```

This is a current, direct confirmation that the exact 32-GiB
qualification TCase cannot run on this host. The existing ARM64 Docker
container is suitable for development builds and bounded tests, but it
cannot satisfy the certified Linux x86-64 contract. No platform gate was
bypassed, no stale binary was substituted, and no capability status was
promoted.

Required external dependency: an authorized Linux x86-64 runner meeting
the roadmap's memory, disk, mapping, sanitizer, and privilege requirements.
R07 additionally requires an independently compiled ClamAV CBC format-8
artifact or compatible compiler.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
