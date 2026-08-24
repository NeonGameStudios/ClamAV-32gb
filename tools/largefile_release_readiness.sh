#!/bin/sh

# The ordinary manifest validator is a coverage contract and permits work that
# is merely bounded or still pending. This opt-in release gate accepts only
# independently qualified or deliberately unsupported capabilities.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
manifest="$root/docs/largefile-capabilities.tsv"
authoritative=1
status_only=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --manifest)
            [ "$#" -ge 2 ] || {
                echo 'missing path after --manifest' >&2
                exit 2
            }
            manifest=$2
            authoritative=0
            shift 2
            ;;
        --status)
            status_only=1
            shift
            ;;
        *)
            echo "usage: $0 [--manifest PATH] [--status]" >&2
            exit 2
            ;;
    esac
done

[ -f "$manifest" ] || {
    echo "release readiness manifest does not exist: $manifest" >&2
    exit 2
}

if [ "$authoritative" -eq 1 ]; then
    sh "$root/tools/largefile_capability_manifest.sh" >/dev/null
fi

hash_file()
{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    else
        echo 'release readiness requires sha256sum or shasum' >&2
        return 1
    fi
}

filter_release_control()
{
    awk 'length($0) >= 67 && substr($0, 67) != "docs/largefile-capabilities.tsv"' "$1"
}

verify_qualified_evidence()
{
    records=$(mktemp "${TMPDIR:-/tmp}/clamav-release-records.XXXXXX")
    unique_records=$(mktemp "${TMPDIR:-/tmp}/clamav-release-unique.XXXXXX")
    current_manifest=$(mktemp "${TMPDIR:-/tmp}/clamav-release-source.XXXXXX")
    current_filtered=$(mktemp "${TMPDIR:-/tmp}/clamav-release-current.XXXXXX")
    evidence_filtered=$(mktemp "${TMPDIR:-/tmp}/clamav-release-evidence.XXXXXX")
    cleanup_release_records()
    {
        rm -f "$records" "$unique_records" "$current_manifest" \
            "$current_filtered" "$evidence_filtered"
    }
    trap cleanup_release_records EXIT HUP INT TERM

    awk -F '\t' '
        NR > 1 && $3 == "qualified" {
            evidence = ""
            source_hash = ""
            build = ""
            count = split($5, tokens, /[ ;]+/)
            for (idx = 1; idx <= count; idx++) {
                if (tokens[idx] ~ /^release_evidence=/)
                    evidence = substr(tokens[idx], length("release_evidence=") + 1)
                else if (tokens[idx] ~ /^source_manifest_sha256=/)
                    source_hash = substr(tokens[idx], length("source_manifest_sha256=") + 1)
                else if (tokens[idx] ~ /^release_build=/)
                    build = substr(tokens[idx], length("release_build=") + 1)
            }
            print evidence "\t" source_hash "\t" build
        }
    ' "$manifest" > "$records"
    LC_ALL=C sort -u "$records" > "$unique_records"

    if [ "$authoritative" -eq 1 ]; then
        sh "$root/tools/largefile_source_manifest.sh" "$root" "$current_manifest"
        filter_release_control "$current_manifest" > "$current_filtered"
    fi

    tab=$(printf '\t')
    while IFS="$tab" read -r evidence_token expected_hash release_build; do
        [ -n "$evidence_token" ] || continue
        evidence_type=${evidence_token%%:*}
        evidence_directory=${evidence_token#*:}
        [ "$evidence_directory" != "$evidence_token" ] || {
            echo "qualified release evidence has no verifier type: $evidence_token" >&2
            return 1
        }
        case "$evidence_directory" in
            /*) ;;
            *)
                echo "qualified release evidence path is not absolute: $evidence_directory" >&2
                return 1
                ;;
        esac
        source_manifest=$evidence_directory/provenance/source-manifest.txt
        [ -f "$source_manifest" ] || {
            echo "qualified release evidence has no source manifest: $source_manifest" >&2
            return 1
        }
        actual_hash=$(hash_file "$source_manifest") || return 1
        [ "$actual_hash" = "$expected_hash" ] || {
            echo "qualified release evidence source manifest hash does not match: $evidence_directory" >&2
            return 1
        }

        case "$evidence_type" in
            runtime)
                [ -z "$release_build" ] || {
                    echo 'runtime release evidence must not specify release_build' >&2
                    return 1
                }
                sh "$root/tools/largefile_runtime_evidence_check.sh" \
                    "$evidence_directory" yes '1 2 4' 33554432 >/dev/null
                ;;
            service)
                case "$release_build" in
                    /*) ;;
                    *)
                        echo 'service release evidence requires an absolute release_build path' >&2
                        return 1
                        ;;
                esac
                sh "$root/tools/largefile_service_evidence_check.sh" \
                    "$evidence_directory" "$release_build" >/dev/null
                ;;
            test)
                [ "$authoritative" -eq 0 ] || {
                    echo 'test evidence is forbidden for the authoritative release manifest' >&2
                    return 1
                }
                [ -z "$release_build" ] || {
                    echo 'test release evidence must not specify release_build' >&2
                    return 1
                }
                ;;
            *)
                echo "unknown qualified release evidence verifier: $evidence_type" >&2
                return 1
                ;;
        esac

        if [ "$authoritative" -eq 1 ]; then
            filter_release_control "$source_manifest" > "$evidence_filtered"
            if ! cmp -s "$current_filtered" "$evidence_filtered"; then
                echo "qualified release evidence does not match the current source outside the release-control manifest: $evidence_directory" >&2
                return 1
            fi
        fi
    done < "$unique_records"

    cleanup_release_records
    trap - EXIT HUP INT TERM
}

summary=$(awk -F '\t' '
    NR == 1 {
        if (NF != 5 || $1 != "kind" || $2 != "id" || $3 != "status" ||
            $4 != "source" || $5 != "evidence_or_required_work") {
            print "invalid capability manifest header" > "/dev/stderr"
            exit 2
        }
        next
    }
    NF != 5 || $1 == "" || $2 == "" || $4 == "" || $5 == "" {
        printf "invalid capability row %d\n", NR > "/dev/stderr"
        exit 2
    }
    $1 != "library" && $1 != "clamscan" && $1 != "clamd" &&
        $1 != "clamdscan" && $1 != "milter" && $1 != "on-access" &&
        $1 != "parser" && $1 != "matcher" && $1 != "feature" &&
        $1 != "unsupported" {
        printf "invalid capability kind at row %d: %s\n", NR, $1 > "/dev/stderr"
        exit 2
    }
    $3 != "qualified" && $3 != "bounded" && $3 != "pending" &&
        $3 != "unsupported" {
        printf "invalid capability status at row %d: %s\n", NR, $3 > "/dev/stderr"
        exit 2
    }
    $1 == "unsupported" && $3 != "unsupported" {
        printf "invalid unsupported capability status at row %d\n", NR > "/dev/stderr"
        exit 2
    }
    $3 == "qualified" {
        release_evidence = ""
        source_manifest_sha256 = ""
        release_evidence_count = 0
        source_manifest_count = 0
        release_build_count = 0
        token_count = split($5, tokens, /[ ;]+/)
        for (token_index = 1; token_index <= token_count; token_index++) {
            if (tokens[token_index] ~ /^release_evidence=/) {
                release_evidence_count++
                release_evidence = substr(tokens[token_index], length("release_evidence=") + 1)
            }
            if (tokens[token_index] ~ /^source_manifest_sha256=/) {
                source_manifest_count++
                source_manifest_sha256 = substr(tokens[token_index], length("source_manifest_sha256=") + 1)
            }
            if (tokens[token_index] ~ /^release_build=/)
                release_build_count++
        }
        if (release_evidence_count != 1 || release_evidence == "" ||
            source_manifest_count != 1 || length(source_manifest_sha256) != 64 ||
            source_manifest_sha256 !~ /^[0-9a-f]+$/ ||
            release_build_count > 1) {
            printf "qualified capability row %d lacks exact revision-bound release evidence\n", NR > "/dev/stderr"
            exit 2
        }
    }
    {
        key = $1 SUBSEP $2
        if (seen[key]++) {
            printf "duplicate capability at row %d: %s:%s\n", NR, $1, $2 > "/dev/stderr"
            exit 2
        }
        total++
        status[$3]++
        if ($3 == "bounded" || $3 == "pending")
            blocked++
        if ($1 == "parser" && $3 != "qualified" && $3 != "unsupported")
            parser_blocked++
    }
    END {
        if (total == 0)
            exit 2
        printf "capability_total=%d\n", total
        printf "capability_qualified=%d\n", status["qualified"]
        printf "capability_bounded=%d\n", status["bounded"]
        printf "capability_pending=%d\n", status["pending"]
        printf "capability_unsupported=%d\n", status["unsupported"]
        printf "capability_blocked=%d\n", blocked
        printf "parser_blocked=%d\n", parser_blocked
    }
' "$manifest") || exit $?

printf '%s\n' "$summary"
blocked=$(printf '%s\n' "$summary" | sed -n 's/^capability_blocked=//p')

if [ "$blocked" -ne 0 ]; then
    echo 'release_readiness=blocked'
    if [ "$status_only" -eq 0 ]; then
        awk -F '\t' 'NR > 1 && ($3 == "bounded" || $3 == "pending") { print $1 "\t" $2 "\t" $3 }' "$manifest" >&2
    fi
    exit 1
else
    verify_qualified_evidence
    if [ "$authoritative" -eq 1 ]; then
        echo 'release_readiness=pass'
    else
        echo 'release_readiness=test-manifest-pass'
    fi
fi
