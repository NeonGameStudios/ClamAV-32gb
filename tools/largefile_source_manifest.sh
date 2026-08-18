#!/bin/sh

# Emit a deterministic content manifest for the source revision used by the
# large-file build/evidence gates.  Git metadata is preferred when available;
# the fallback deliberately hashes the source snapshot itself so a Git-less
# delivery cannot silently use an unbound or moving revision.
#
# Usage: tools/largefile_source_manifest.sh SOURCE_ROOT OUTPUT_FILE

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 SOURCE_ROOT OUTPUT_FILE" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$1" && pwd)
output=$2

case "$output" in
    /*) ;;
    *) output=$(pwd)/$output ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
    hash_file()
    {
        sha256sum "$1" | awk '{ print $1 }'
    }
else
    hash_file()
    {
        shasum -a 256 "$1" | awk '{ print $1 }'
    }
fi

mkdir -p "$(dirname "$output")"
temporary="$output.tmp.$$"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

is_git_checkout=no
if command -v git >/dev/null 2>&1 &&
    [ "$(git -C "$root" rev-parse --is-inside-work-tree 2>/dev/null || true)" = true ]; then
    is_git_checkout=yes
fi

if [ "$is_git_checkout" = yes ]; then
    git -C "$root" ls-files | while IFS= read -r relative; do
        [ -n "$relative" ] || continue
        file="$root/$relative"
        [ -f "$file" ] || continue
        printf '%s  %s\n' "$(hash_file "$file")" "$relative"
    done
else
    # The fallback is for source snapshots without .git.  Exclude generated
    # build/dependency payloads and the large source archive that may be used
    # to transport a snapshot to Sonic1; source files and audit controls stay
    # in the immutable manifest.
    find "$root" -type f \
        -not -path "$root/.git/*" \
        -not -path "$root/.codex/*" \
        -not -path "$root/build*/*" \
        -not -path "$root/target/*" \
        -not -name '*.tar.gz' \
        -not -name 'libnull.a' \
        -print | LC_ALL=C sort | while IFS= read -r file; do
            relative=${file#"$root"/}
            printf '%s  %s\n' "$(hash_file "$file")" "$relative"
        done
fi | LC_ALL=C sort > "$temporary"

mv "$temporary" "$output"
trap - EXIT HUP INT TERM
