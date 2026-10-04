# R13 Sonic1 v16 PCRE detection diagnostic — 2026-09-27

## Provenance and execution

Host/profile: `sonic1` / `sonic1-camera-key`. Container:
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`;
image ID `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The deterministic source package was
`/qualification/source-qual-20260927-v16-5e667453.tar.gz`, SHA-256
`86d8e56063ffb6e5876c8d73dcf45ae5ac82e24ded4a07f25eeabd33fba04100`;
the extracted source manifest was regenerated and matched byte-for-byte,
SHA-256 `5e6674538e2c88359a5fca3bd14e5e5909a007d6afec1eef1c82896b30cc5b25`.
The v16 Release CMake cache SHA-256 was
`60718d16224323c449ffa450cd6297a19709098871ce07863fefd7c88a6c85e8`, and
the `clamscan` SHA-256 was
`457786653d2578313129b12076163511de636d80265dae271770c0713c8f5fe6`.
The 31 non-exact Release CTest targets passed (`job_190110e1b0764acd806bd3741f86af61`),
and `largefile_library_exact_32g` passed in 333.72 seconds
(`job_08795ddf0a484aa4ae94eae878449387`).

The test fixture `/ram/edge-stable.bin` was independently rehashed as
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
It is exactly 34,359,738,368 bytes, fully allocated, has `SEEK_DATA(0)=0`,
`SEEK_HOLE(0)=34359738368`, and contains `EDGE-LATE-MARKER` at EOF−16.

## PCRE result

Tracked capture `job_6653b81fb2ba422d904886fc98ab5629` ran the v16 Release
scanner with separate detection DB
`3b7056c08f3bb0e2e0f86a71efe90bb0035cb7503844b6cbf5fd390c65087e8f`.
Its report records `DETECTION_TERMINATED`, exact root/contiguous size,
`PcreTail32G.UNOFFICIAL`, and zero skipped operations. The runtime debug log
orders before-PCRE, full 32-GiB PCRE subject, exact match offset
`34359738352`, subject release, and deep-parse dispatch for object 0.

The raw capture contains 1,487 samples. Its resource row reports a PCRE peak
of 33,642,068 KiB, post-PCRE peak of 87,636 KiB, zero swap, zero new OOM
events/kills, and zero temporary peak. The 40-GiB PCRE-phase and below-12-GiB
post-PCRE limits are met. The separate strict 32-GiB whole-workload ceiling
is not met by this run.

## Evidence limitation and correction

The proof is **diagnostic, not promotable**. The capture watcher acknowledged
the post-PCRE rendezvous before appending its independent event sample. The
regular sampler therefore recorded two deep-parse rows before the delayed
post-PCRE event row. The ordered runtime debug log and phase protocol confirm
the application transition, but the raw resource trace itself has invalid
phase order for the fail-closed v2 verifier.

The capture utility has since been changed to append the independent event
sample under the shared sample lock before writing the acknowledgement. A
regression test now requires raw pcre → post-PCRE → deep-parse sample order.
The verifier also checks that the CMake build cache binds both recorded
source identity fields to the proof manifest. This v16 diagnostic cannot
retroactively prove the corrected capture path; a fresh source package,
matching build identity, and two new scanner processes are required.

No volume was resized, software installed, capability promoted, GitHub
workflow triggered, or Git commit/push made.
