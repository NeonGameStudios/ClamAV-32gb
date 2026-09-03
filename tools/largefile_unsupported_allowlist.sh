#!/bin/sh

# Shared release-control data for capabilities that are deliberately outside
# the first production target. This file is sourced by the manifest and
# release-readiness validators; it is intentionally not derived from the
# candidate manifest being validated.

largefile_deliberate_unsupported_ids='native-windows-memory-scan macos-first-release aarch64-first-release autoit-ea05-output-over-4g bytecode-v1-over-4g elf-legacy-metadata-over-4g egg-compat-member-over-1g egg-legacy-string-metadata-over-1g legacy-callback-over-1g image-fuzzy-over-contiguous-limit onenote-modern-over-256m xar-subdocument-over-1g mail-legacy-materialization-over-64m pe32plus-legacy-x86-analysis pe-legacy-metadata-over-4g pe-unpacker-over-1g pdf-stream-over-1g vba-callback-over-1g vba-project-directory-without-file-mapping'
largefile_required_unsupported_ids='macos-first-release aarch64-first-release autoit-ea05-output-over-4g bytecode-v1-over-4g egg-compat-member-over-1g egg-legacy-string-metadata-over-1g elf-legacy-metadata-over-4g legacy-callback-over-1g image-fuzzy-over-contiguous-limit pe32plus-legacy-x86-analysis pdf-stream-over-1g vba-callback-over-1g vba-project-directory-without-file-mapping'

largefile_unsupported_id_is_allowed()
{
    largefile_candidate_id=$1
    for largefile_allowed_id in $largefile_deliberate_unsupported_ids; do
        if [ "$largefile_candidate_id" = "$largefile_allowed_id" ]; then
            return 0
        fi
    done
    return 1
}

largefile_validate_unsupported_kind_rows()
{
    largefile_manifest_path=$1
    largefile_unsupported_ids=$(awk -F '\t' \
        '$1 == "unsupported" { print $2 }' "$largefile_manifest_path")
    for largefile_unsupported_id in $largefile_unsupported_ids; do
        if ! largefile_unsupported_id_is_allowed "$largefile_unsupported_id"; then
            echo "unapproved deliberate unsupported capability ${largefile_unsupported_id}" >&2
            return 1
        fi
    done
}
