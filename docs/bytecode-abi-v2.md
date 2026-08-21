# ClamAV bytecode ABI v2

Bytecode format functionality level `8` (`BC_FORMAT_LEVEL_V2`) is the
64-bit-coordinate ABI. It is loaded by the existing bytecode loader and can
run in either the interpreter or the LLVM JIT.

## Compatibility rules

- Format levels 6 and 7 retain their existing ABI and API numbering.
- Format level 8 appends new globals and API entries; it does not renumber or
  change any v1 entry.
- v1 bytecode is admitted only when the mapped input and every logical match
  offset fit the legacy representable range. If a v1 hook or logical bytecode
  would run on a larger layer, the engine marks the scan incomplete instead of
  truncating a coordinate.
- v2 bytecode receives the full mapped file size and native 64-bit logical
  match offsets. The byte buffer argument and allocation sizes remain bounded
  by their existing 32-bit API contracts.

## v2 globals

The following globals are available only to format level 8 bytecode:

| Global | Type | Meaning |
| --- | --- | --- |
| `__clambc_filesize64` | `uint64_t[1]` | Size of the current mapped input |
| `__clambc_match_offsets64` | `uint64_t[64]` | First match offset for each logical-signature subexpression; `CLI_OFF_NONE64` means no match |

## v2 APIs

The following entries are appended after the v1 API table:

| API | Result | Arguments |
| --- | --- | --- |
| pdf_getobjsize64 | uint64_t | int32_t |
| pdf_get_offset64 | uint64_t | int32_t |
| `read64` | `int64_t` | `uint8_t *`, `uint32_t` |
| `seek64` | `int64_t` | `int64_t`, `uint32_t` |
| `file_find64` | `int64_t` | `const uint8_t *`, `uint32_t` |
| `file_byteat64` | `int32_t` | `uint64_t` |
| `file_find_limit64` | `int64_t` | `const uint8_t *`, `uint32_t`, `uint64_t` |
| `buffer_pipe_new_fromfile64` | `int32_t` | `uint64_t` |
| `buffer_pipe_read_avail64` | `uint64_t` | `int32_t` |

The interpreter and JIT use separate typed dispatch tables for these entries.
The v2 PDF bridge also exposes native-width object size and offset accessors.
The v1 PDF size and offset APIs remain unchanged; on a large PDF layer the v1
offset accessor returns its existing invalid sentinel instead of silently
wrapping.

File-backed `buffer_pipe_read_get()` windows are borrowed until the matching
`buffer_pipe_read_stopped()` call; the engine releases the fmap page locks at
that boundary and again during buffer teardown. `pdf_getobj()` has no matching
release entry in the historical ABI, so its returned object view is bounded
and unlocked. Bytecode must consume that view during the hook and must not
retain the pointer across later fmap operations.
All read, seek, search, and byte-at operations reject offsets that cannot be
represented by the host mapping or by the signed result type. A failed read
or coordinate conversion is fail-visible through the scan-incomplete report.

When a hook table mixes ABI generations, a v1 hook that cannot represent the
large layer is recorded as incomplete and skipped; later applicable v2 hooks
still run. The final scan remains non-clean and non-cacheable because the v1
detector was unavailable, but a compatible v2 detector cannot be suppressed by
the legacy failure.

## Qualification requirement

Qualification requires an independently compiled format-8 fixture.

The repository does not contain the external bytecode compiler. A release
qualification run must therefore include at least one independently compiled
format-8 fixture exercising the v2 globals, a cross-4-GiB read/seek/search,
and both interpreter and JIT execution. The in-tree unit test verifies the
host API boundary with a synthetic 4-GiB-plus map; it is not a substitute for
that compiler-produced fixture.
