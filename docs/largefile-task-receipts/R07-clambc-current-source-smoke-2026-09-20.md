# Task receipt: R07 current-source `clambc` smoke

Task ID / parent milestone: `R07` / `R04`

Scope: verify that the current-source bytecode test executable still builds
and starts in the disposable Sonic1 build. This is implementation-health
evidence only; it is not independent format-8 qualification.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.
- The source tree contains the object-bound PCRE changes from commit
  `09789b1b`; the current local repository receipt commit is later than that
  source change.

Commands and results:

```text
make -C /src/build-roadmap-20260920 -j2 clambc
exit=0

/src/build-roadmap-20260920/clambc/clambc --version
exit=0
Clam AntiVirus Bytecode Testing Tool 1.5.3-largefile-devel
LLVM is not compiled or not linked
```

Interpretation:

- The current-source `clambc` executable links and starts successfully.
- The build does not contain LLVM/JIT support, so it cannot provide the
  required interpreter-plus-JIT R07 qualification evidence.
- The repository still has no authorized independently compiled format-8
  CBC fixture or compatible external compiler. The existing ABI/unit tests
  remain development controls, not a substitute for that artifact.

Remaining dependency:

- Provide an authorized compatible format-8 compiler or independently
  compiled format-8 artifact, with source identity and hash, on a qualifying
  Linux x86-64 runner. Until then `matcher:bytecode` remains pending.

State: `development-verified; blocked-external-prerequisite`
