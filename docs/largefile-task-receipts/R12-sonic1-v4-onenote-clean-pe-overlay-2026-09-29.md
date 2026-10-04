# R12 Sonic1 v4 clean OneNote and PE-overlay diagnosis — 2026-09-29

This is a failed clean-completion case, not a qualification pass. The v4
source-bound Release `clamscan` (SHA-256
`064be4e7f5b9b3d8f65c2ea09d12d28babb288fb98f7b435a350fc1a575a8479`,
source manifest
`1ab7e63f3b74eb987e2eef9b79a672e4fedab83bda83ed13c9895ad9bf8e1ff0`)
scanned the fully materialized 32-GiB OneNote fixture in the pinned Sonic1
container using an isolated clean-control NDB. The control signature is
`NDB.Clamav-Unit-Test-Signature:0:*:434c414d41562d544553542d535452494e472d4e4f542d4549434152`
(database SHA-256
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`).
The independent full-byte oracle read exactly 34,359,738,368 bytes, found
zero occurrences of its literal, verified fixture SHA-256
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`,
and reported no holes before EOF. Its result is retained at
`/qualification/r12-v4-onenote32g-clean-20260929-release/provenance/oracle-result.jsonl`
(SHA-256 `f36d13d05f436c6b1ee2b1e31daea156c7fb93c8deb5bce9bd4335c30c4e801e`).

Managed scan job `job_5f56edc59e2e4c72abc18245f22d6ad3` exited 2 after
about 200 seconds. Its scan report recorded `status=27`,
`completion=MALFORMED_CONFIRMED`, file type `CL_TYPE_ONENOTE`, root bytes
34,359,738,368, logical bytes 34,359,738,912, matcher bytes
34,368,129,568, temporary bytes 34,359,720,552, two scanned files,
two parser operations, and reason
`InstallShield file record contained an invalid size or range`.
The case-private temporary directory was empty afterward. Resource sampling
recorded peak process-tree RSS of 99,384 KiB, zero swap and zero OOM kills;
this is not a resource-limit completion.

The same v4 scanner and clean database reproduced the exact failure on the
original 52,297-byte `clam.exe.webapp-export.one` and on its 544-byte
embedded `clam.exe`. A bounded read at the large OneNote's late marker
offset 34,359,719,413 hashed the embedded 544 bytes to
`71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495`,
matching the direct PE scan. The PE section table ends at byte 544, while
the prior overlay calculation begins inside those headers at about byte
513. The optional InstallShield parser treats the header bytes as a weak
candidate and sets sticky incomplete state. This is a small PE parsing
defect exposed by the deep OneNote scan, not a 32-GiB offset or disk-spool
failure.

The next candidate clamps the PE overlay start after the consumed section
table and adds a regression covering the bare PE and a genuinely appended
overlay. It is frozen in a fresh deterministic v5 archive (17,907,029
bytes, SHA-256
`f046a4cd88b6bfb265ba6dd531c3415c90d6f6ac81c0608f29b3df6727894b0d`)
with source manifest
`19c087939965455bce3d8bb011532e0fab1604c1620953e50301236dcb130bcf`.
MCP-SSH transfer `transfer_c7062f4597a74f9b9d3d5910c5b16367` completed
with atomic commit; independent Sonic1 archive SHA-256 matched. Extracted
bytes regenerated the embedded manifest exactly. This receipt does **not**
claim the v5 behavior until build and scans finish.
