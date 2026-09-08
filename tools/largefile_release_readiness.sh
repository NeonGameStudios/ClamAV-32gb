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
        --test-manifest)
            [ "$#" -ge 2 ] || {
                echo 'missing path after --test-manifest' >&2
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
            echo "usage: $0 [--test-manifest PATH] [--status]" >&2
            exit 2
            ;;
    esac
done

[ -f "$manifest" ] || {
    echo "release readiness manifest does not exist: $manifest" >&2
    exit 2
}

. "$root/tools/largefile_unsupported_allowlist.sh"
if ! largefile_validate_unsupported_kind_rows "$manifest"; then
    exit 2
fi

if [ "$authoritative" -eq 1 ]; then
    sh "$root/tools/largefile_capability_manifest.sh" >/dev/null
    if ! command -v python3 >/dev/null 2>&1; then
        echo 'authoritative readiness requires python3 for capability-case coverage validation' >&2
        exit 2
    fi
    python3 -B "$root/tools/largefile_acceptance_cases.py" \
        --manifest "$manifest" \
        --map "$root/docs/largefile-capability-case-map.tsv" \
        --check-map >/dev/null
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

verify_capability_binding()
{
    evidence_directory=$1
    expected_kind=$2
    expected_id=$3
    expected_source_hash=$4
    expected_evidence_type=$5
    binding_file=$evidence_directory/provenance/capability-bindings.tsv

    [ -f "$binding_file" ] || {
        echo "qualified release evidence has no capability binding manifest: $binding_file" >&2
        return 1
    }

    binding=$(awk -F '\t' -v wanted_kind="$expected_kind" -v wanted_id="$expected_id" '
        NR == 1 {
            if (NF != 6 || $1 != "kind" || $2 != "id" || $3 != "status" ||
                $4 != "source_manifest_sha256" || $5 != "proof" || $6 != "proof_sha256")
                invalid = 1
            next
        }
        {
            if (NF != 6 || $1 == "" || $2 == "" || $3 == "" || $4 == "" || $5 == "" || $6 == "") {
                invalid = 1
                next
            }
            if ($3 != "qualified" || length($4) != 64 || $4 !~ /^[0-9a-f]+$/ ||
                length($6) != 64 || $6 !~ /^[0-9a-f]+$/) {
                invalid = 1
            }
            key = $1 SUBSEP $2
            seen_key[key] = seen_key[key] + 1
            if (seen_key[key] > 1)
                invalid = 1
            seen_proof[$5] = seen_proof[$5] + 1
            if (seen_proof[$5] > 1)
                invalid = 1
            if ($1 == wanted_kind && $2 == wanted_id) {
                matches++
                record = $4 "\t" $5 "\t" $6
            }
        }
    END {
        if (invalid || matches != 1)
            exit 1
        print record
    }
    ' "$binding_file") || {
        echo "qualified release evidence has no unique valid binding for ${expected_kind}:${expected_id}" >&2
        return 1
    }

    binding_tab=$(printf '\t')
    binding_source_hash=
    proof=
    proof_hash=
    IFS="$binding_tab" read -r binding_source_hash proof proof_hash <<EOF
$binding
EOF
    [ "$binding_source_hash" = "$expected_source_hash" ] || {
        echo "qualified release evidence binding source hash does not match for ${expected_kind}:${expected_id}" >&2
        return 1
    }
    case "$proof" in
        ''|/*|.|..|../*|*/../*|*/..|*/.|*/..)
            echo "qualified release evidence proof path is unsafe for ${expected_kind}:${expected_id}" >&2
            return 1
            ;;
    esac
    proof_path=$evidence_directory/$proof
    [ -f "$proof_path" ] && [ ! -L "$proof_path" ] || {
        echo "qualified release evidence proof is missing or symlinked for ${expected_kind}:${expected_id}: $proof" >&2
        return 1
    }
    actual_proof_hash=$(hash_file "$proof_path") || return 1
    [ "$actual_proof_hash" = "$proof_hash" ] || {
        echo "qualified release evidence proof hash does not match for ${expected_kind}:${expected_id}" >&2
        return 1
    }

    # A unique proof pathname and hash are not enough: a copied or generic
    # artifact must identify the exact capability and evidence verifier it
    # claims to qualify. Keep this binding metadata deliberately small and
    # machine-readable so every verifier can produce it alongside its proof.
    if ! awk -F '=' -v wanted_kind="$expected_kind" -v wanted_id="$expected_id" \
        -v wanted_source="$expected_source_hash" -v wanted_type="$expected_evidence_type" '
        $1 == "proof_format_version" && NF == 2 { version++; valid_version = ($2 == "1") }
        $1 == "capability_kind" && NF == 2 { kind++; valid_kind = ($2 == wanted_kind) }
        $1 == "capability_id" && NF == 2 { id++; valid_id = ($2 == wanted_id) }
        $1 == "source_manifest_sha256" && NF == 2 { source++; valid_source = ($2 == wanted_source) }
        $1 == "evidence_type" && NF == 2 { evidence++; valid_evidence = ($2 == wanted_type) }
        $1 == "qualification_result" && NF == 2 { result++; valid_result = ($2 == "pass") }
        END {
            exit !(version == 1 && valid_version && kind == 1 && valid_kind &&
                   id == 1 && valid_id && source == 1 && valid_source &&
                   evidence == 1 && valid_evidence && result == 1 && valid_result)
        }
    ' "$proof_path"; then
        echo "qualified release evidence proof is not self-bound to ${expected_evidence_type}:${expected_kind}:${expected_id}" >&2
        return 1
    fi
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
            print $1 "\t" $2 "\t" evidence "\t" source_hash "\t" build
        }
    ' "$manifest" > "$records"
    LC_ALL=C sort -u "$records" > "$unique_records"

    if [ "$authoritative" -eq 1 ]; then
        sh "$root/tools/largefile_source_manifest.sh" "$root" "$current_manifest"
        filter_release_control "$current_manifest" > "$current_filtered"
    fi

    tab=$(printf '\t')
    while IFS="$tab" read -r capability_kind capability_id evidence_token expected_hash release_build; do
        [ -n "$evidence_token" ] || continue
        evidence_type=${evidence_token%%:*}
        evidence_directory=${evidence_token#*:}
        [ "$evidence_directory" != "$evidence_token" ] || {
            echo "qualified release evidence has no verifier type: $evidence_token" >&2
            return 1
        }
        case "$evidence_type" in
            runtime|service|test) ;;
            *)
                echo "unknown qualified release evidence verifier: $evidence_type" >&2
                return 1
                ;;
        esac
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
        verify_capability_binding "$evidence_directory" "$capability_kind" \
            "$capability_id" "$expected_hash" "$evidence_type"

        # On-access permission qualification is the only capability whose
        # release proof must include real kernel permission events. A generic
        # service or client record cannot prove fanotify allow/deny behavior;
        # keep this check at the authoritative evidence boundary so missing
        # privilege or observability remains a blocker.
        if [ "$capability_kind" = on-access ] && [ "$capability_id" = permission ]; then
            fanotify_proof=$evidence_directory/provenance/fanotify-permission-evidence.json
            [ -f "$fanotify_proof" ] && [ ! -L "$fanotify_proof" ] || {
                echo "qualified on-access evidence has no fanotify permission proof: $fanotify_proof" >&2
                return 1
            }
            python3 -B "$root/tools/largefile_fanotify_evidence.py" \
                "$fanotify_proof" --evidence-root "$evidence_directory" >/dev/null || {
                echo "qualified on-access evidence has invalid fanotify permission proof: $fanotify_proof" >&2
                return 1
            }
        fi

        # PCRE's 40-GiB full-subject allowance and <12-GiB post-subject
        # requirement are phase contracts, not metadata labels. Require the
        # retained process-tree samples and exact-tail proof whenever the
        # matcher row is promoted to qualified status.
        if [ "$capability_kind" = matcher ] && [ "$capability_id" = pcre ]; then
            pcre_phase_proof=$evidence_directory/provenance/pcre-rss-phase-evidence.json
            [ -f "$pcre_phase_proof" ] && [ ! -L "$pcre_phase_proof" ] || {
                echo "qualified PCRE evidence has no phase RSS proof: $pcre_phase_proof" >&2
                return 1
            }
            python3 -B "$root/tools/largefile_pcre_phase_evidence.py" \
                "$pcre_phase_proof" --evidence-root "$evidence_directory" >/dev/null || {
                echo "qualified PCRE evidence has invalid phase RSS proof: $pcre_phase_proof" >&2
                return 1
            }
        fi

        if [ "$authoritative" -eq 1 ]; then
            acceptance_records=$evidence_directory/provenance/acceptance-cases.tsv
            [ -f "$acceptance_records" ] && [ ! -L "$acceptance_records" ] || {
                echo "qualified release evidence has no capability-specific acceptance records: $acceptance_records" >&2
                return 1
            }
            python3 -B "$root/tools/largefile_acceptance_cases.py" \
                --manifest "$root/docs/largefile-capabilities.tsv" \
                --map "$root/docs/largefile-capability-case-map.tsv" \
                --records "$acceptance_records" \
                --check-records \
                --evidence-root "$evidence_directory" \
                --require-capability "$capability_kind" "$capability_id" >/dev/null || {
                echo "qualified release evidence lacks required cases for ${capability_kind}:${capability_id}" >&2
                return 1
            }
        fi

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
        if ($3 == "bounded" || $3 == "pending" ||
            ($3 == "unsupported" && $1 != "unsupported"))
            blocked++
        if ($3 == "unsupported" && $1 != "unsupported")
            unsupported_required++
        if ($1 == "parser" && $3 != "qualified")
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
        printf "capability_unsupported_required=%d\n", unsupported_required
        printf "capability_blocked=%d\n", blocked
        printf "parser_blocked=%d\n", parser_blocked
    }
' "$manifest") || exit $?

printf '%s\n' "$summary"
blocked=$(printf '%s\n' "$summary" | sed -n 's/^capability_blocked=//p')

if [ "$blocked" -ne 0 ]; then
    echo 'release_readiness=blocked'
    if [ "$status_only" -eq 0 ]; then
        awk -F '\t' 'NR > 1 && ($3 == "bounded" || $3 == "pending" ||
            ($3 == "unsupported" && $1 != "unsupported")) {
                if ($3 == "unsupported" && $1 != "unsupported")
                    print "unsupported required capability\t" $1 "\t" $2
                else
                    print $1 "\t" $2 "\t" $3
            }' "$manifest" >&2
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
