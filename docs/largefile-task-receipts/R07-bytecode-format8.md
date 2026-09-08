# Task receipt: R07 independent format-8 bytecode dependency audit

Task ID / parent milestone: `R07` / `R00`

Scope: locate an independently available compatible format-8 bytecode
compiler or retained compiler-produced artifact. This is a prerequisite audit,
not bytecode qualification.

Checks performed (repeated on 2026-09-05 from the canonical checkout at
`ff8905891b2b58a66c71859ab2c807cc4dee2dec`):

- `command -v clambc` found no installed executable. The in-tree `clambc`
  source is an analyzer/runner, not the external compiler required by the
  roadmap.
- No LLVM bytecode compiler tool (`llvm-as`, `llvm-ld`, or `llc`) was present
  on the host.
- Repository bytecode files are existing format-7/legacy or unit fixtures;
  none is independently compiled format 8. `docs/bytecode-abi-v2.md`
  explicitly requires a compiler-produced fixture exercising v2 globals,
  cross-4-GiB read/seek/search, and interpreter/JIT execution.
- No dependency was installed, downloaded, or contacted. The CMake workflow
  was not changed or triggered.

The availability audit also searched the current checkout, its existing
`unit_tests/input/bytecode_sigs` fixtures, `/private/tmp` build/evidence
directories, and the locally visible `/usr`, `/opt`, `/Applications`, and
`/Volumes` trees. The repository fixtures are legacy/format-7 controls and the
temporary build outputs contain only compiled objects; no independently
compiled format-8 artifact or compatible compiler was found. The host PATH
also has no `clambc`, `clambc-compiler`, or `sigtool` executable.

The in-tree synthetic v2 host-API test and the synthetic 4-GiB-plus map test
remain useful negative/unit controls. They deliberately do not satisfy the
independent compiler, exact-result/offset, interpreter/JIT, or sanitizer
requirements in `docs/bytecode-abi-v2.md`.

Conclusion: R07 cannot produce its required independent fixture on this host.
The exact missing dependency is a compatible ClamAV bytecode compiler/toolchain
that emits format-8 CBC artifacts, plus an authorized current-source x86-64
runner/build for interpreter/JIT and sanitizer execution. Existing synthetic
host-API and mutated-format tests remain useful negative/unit controls but
cannot qualify the capability.

State: `blocked-by-external-compiler`; release readiness remains blocked.
