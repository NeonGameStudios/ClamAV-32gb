#!/bin/sh

# Generate sparse files with unique markers around the 2 GiB, 4 GiB, 8 GiB,
# 16 GiB, and 32 GiB boundaries. The output directory is intentionally
# supplied by the caller so large sparse fixtures are never created by
# accident in the source tree.
# Usage: tools/largefile_boundary_corpus.sh /path/to/output-directory

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
fi

out=$1
mkdir -p "$out"
manifest=$out/manifest.tsv
printf 'file\tmarker\toffset\tsize\tkind\n' > "$manifest"

make_marker() {
    label=$1
    offset=$2
    marker="CLAMAV-LF-${label}"
    file="$out/${label}.bin"
    size=$((offset + 64))

    truncate -s "$size" "$file"
    printf '%s' "$marker" | dd of="$file" bs=1 seek="$offset" conv=notrunc >/dev/null 2>&1
    printf '%s\t%s\t%s\t%s\t%s\n' "${label}.bin" "$marker" "$offset" "$size" sparse-boundary >> "$manifest"
}

make_marker 2g-minus 2147483647
make_marker 2g       2147483648
make_marker 2g-plus  2147483649
make_marker 4g-minus-two 4294967294
make_marker 4g-minus 4294967295
make_marker 4g       4294967296
make_marker 4g-plus  4294967297
make_marker 8g       8589934592
make_marker 16g      17179869184

# A full-size 32 GiB file with an early marker proves that the file-size
# parser and top-level limit accept 32 GiB without requiring a full 32 GiB
# traversal. The edge case below separately measures the cost of reaching
# the final boundary marker.
head_label=32g-head
head_file="$out/${head_label}.bin"
head_size=34359738368
head_offset=4096
head_marker=CLAMAV-LF-32G-HEAD
truncate -s "$head_size" "$head_file"
printf '%s' "$head_marker" | dd of="$head_file" bs=1 seek="$head_offset" conv=notrunc >/dev/null 2>&1
printf '%s\t%s\t%s\t%s\t%s\n' "${head_label}.bin" "$head_marker" "$head_offset" "$head_size" sparse-boundary >> "$manifest"

# Keep this fixture exactly 32 GiB while placing a marker in its final 64
# bytes, so the test remains inside the LargeFile 1.0 target range.
edge_label=32g-edge
edge_file="$out/${edge_label}.bin"
edge_size=34359738368
edge_offset=34359738304
edge_marker=CLAMAV-LF-32G-EDGE
truncate -s "$edge_size" "$edge_file"
printf '%s' "$edge_marker" | dd of="$edge_file" bs=1 seek="$edge_offset" conv=notrunc >/dev/null 2>&1
printf '%s\t%s\t%s\t%s\t%s\n' "${edge_label}.bin" "$edge_marker" "$edge_offset" "$edge_size" sparse-boundary >> "$manifest"

# Do not let a malformed or truncated fixture become the scanner's oracle.
# The checker reads only each marker window and independently verifies the
# reviewed row set, logical size, sparse allocation, and marker bytes.
python3 "$root/tools/largefile_boundary_corpus_check.py" "$out"

echo "Generated sparse boundary corpus in $out"
echo "Manifest: $manifest"
