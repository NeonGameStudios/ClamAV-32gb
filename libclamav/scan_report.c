/*
 * Structured scan reports.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "scan_report.h"

#include "clamav_rust.h"
#include "others.h"

#include <json.h>
#include <sys/time.h>

#include <stdlib.h>
#include <string.h>

static uint64_t report_now_usec(void)
{
    struct timeval now;

    if (gettimeofday(&now, NULL) != 0)
        return 0;

    return ((uint64_t)now.tv_sec * 1000000ULL) + (uint64_t)now.tv_usec;
}

static char *report_strdup(const char *value)
{
    if (NULL == value)
        return NULL;

    return strdup(value);
}

static void report_replace_string(
    cl_scan_report_t *report,
    char **destination,
    const char *value)
{
    char *copy;

    if (NULL == value) {
        free(*destination);
        *destination = NULL;
        return;
    }

    copy = report_strdup(value);
    if (NULL == copy) {
        if (NULL != report)
            report->string_allocation_failed = true;
        return;
    }

    free(*destination);
    *destination = copy;
}

static void report_get_engine_limit(
    const struct cl_engine *engine,
    enum cl_engine_field field,
    uint64_t *destination)
{
    int status = CL_ERROR;
    long long value;

    if (NULL == destination)
        return;

    *destination = 0;
    if (NULL == engine)
        return;

    value = cl_engine_get_num(engine, field, &status);
    if (CL_SUCCESS == status && value >= 0)
        *destination = (uint64_t)value;
}

static const char *report_completion_name(cl_scan_completion_t completion)
{
    switch (completion) {
        case CL_SCAN_COMPLETION_COMPLETE:
            return "COMPLETE";
        case CL_SCAN_COMPLETION_DETECTION_TERMINATED:
            return "DETECTION_TERMINATED";
        case CL_SCAN_COMPLETION_LIMIT_INCOMPLETE:
            return "LIMIT_INCOMPLETE";
        case CL_SCAN_COMPLETION_UNSUPPORTED:
            return "UNSUPPORTED";
        case CL_SCAN_COMPLETION_MALFORMED_CONFIRMED:
            return "MALFORMED_CONFIRMED";
        case CL_SCAN_COMPLETION_RESOURCE_FAILURE:
            return "RESOURCE_FAILURE";
        case CL_SCAN_COMPLETION_APPLICATION_ABORT:
            return "APPLICATION_ABORT";
        default:
            return "UNKNOWN";
    }
}

static bool report_reason_contains(const char *reason, const char *needle)
{
    return (NULL != reason) && (NULL != needle) && (NULL != strstr(reason, needle));
}

static bool report_reason_is_unsupported(const char *reason)
{
    return report_reason_contains(reason, "unsupported") ||
           report_reason_contains(reason, "not implemented") ||
           report_reason_contains(reason, "requires") ||
           report_reason_contains(reason, "unavailable") ||
           report_reason_contains(reason, "encrypted") ||
           report_reason_contains(reason, "encryption") ||
           report_reason_contains(reason, "ciphertext") ||
           report_reason_contains(reason, "legacy ABI") ||
           report_reason_contains(reason, "cannot represent");
}

static bool report_status_is_operational_failure(cl_error_t status)
{
    switch (status) {
        case CL_EOPEN:
        case CL_ECREAT:
        case CL_EUNLINK:
        case CL_ESTAT:
        case CL_EREAD:
        case CL_ESEEK:
        case CL_EWRITE:
        case CL_EDUP:
        case CL_EACCES:
        case CL_ETMPFILE:
        case CL_ETMPDIR:
        case CL_EMAP:
        case CL_EMEM:
        case CL_ELOCK:
        case CL_EBUSY:
        case CL_ESTATE:
        case CL_ERROR:
            return true;
        default:
            return false;
    }
}

static int report_completion_rank(cl_scan_completion_t completion)
{
    switch (completion) {
        case CL_SCAN_COMPLETION_DETECTION_TERMINATED:
            return 7;
        case CL_SCAN_COMPLETION_RESOURCE_FAILURE:
            return 6;
        case CL_SCAN_COMPLETION_LIMIT_INCOMPLETE:
            return 5;
        case CL_SCAN_COMPLETION_MALFORMED_CONFIRMED:
            return 4;
        case CL_SCAN_COMPLETION_UNSUPPORTED:
            return 3;
        case CL_SCAN_COMPLETION_APPLICATION_ABORT:
            return 2;
        case CL_SCAN_COMPLETION_COMPLETE:
            return 0;
        default:
            return 1;
    }
}

static void report_add_u64(uint64_t *destination, uint64_t value)
{
    if (UINT64_MAX - *destination < value)
        *destination = UINT64_MAX;
    else
        *destination += value;
}

static cl_error_t report_json_add_owned(json_object *object, const char *key, json_object *value)
{
    if (json_object_object_add(object, key, value) != 0) {
        if (value)
            json_object_put(value);
        return CL_EMEM;
    }

    return CL_SUCCESS;
}

static cl_error_t report_json_add_u64(
    json_object *object,
    const char *key,
    uint64_t value)
{
    json_object *number;

    if ((NULL == object) || (NULL == key))
        return CL_ENULLARG;

#if JSON_C_MINOR_VERSION >= 14
    number = json_object_new_uint64(value);
#else
    /* Older json-c releases have no unsigned integer JSON type. Do not
     * convert a saturated counter above INT64_MAX into a negative number. */
    if (value > INT64_MAX)
        return CL_EARG;
    number = json_object_new_int64((int64_t)value);
#endif
    if (NULL == number)
        return CL_EMEM;

    return report_json_add_owned(object, key, number);
}

static cl_error_t report_json_add_int(
    json_object *object,
    const char *key,
    int value)
{
    json_object *number;

    if ((NULL == object) || (NULL == key))
        return CL_ENULLARG;

    number = json_object_new_int(value);
    if (NULL == number)
        return CL_EMEM;

    return report_json_add_owned(object, key, number);
}

static cl_error_t report_json_add_string(
    json_object *object,
    const char *key,
    const char *value)
{
    json_object *string;

    if ((NULL == object) || (NULL == key) || (NULL == value))
        return CL_ENULLARG;

    string = json_object_new_string(value);
    if (NULL == string)
        return CL_EMEM;

    return report_json_add_owned(object, key, string);
}

/* Report counters are diagnostic evidence, not scan-control state. Saturate
 * them rather than allowing an adversarially large directory or parser walk
 * to wrap a count back to zero in the serialized report. */
static void report_increment_u64(uint64_t *value)
{
    if ((NULL != value) && (*value != UINT64_MAX))
        (*value)++;
}

static int report_verdict_rank(cl_verdict_t verdict)
{
    switch (verdict) {
        case CL_VERDICT_STRONG_INDICATOR:
            return 4;
        case CL_VERDICT_POTENTIALLY_UNWANTED:
            return 3;
        case CL_VERDICT_TRUSTED:
            return 2;
        case CL_VERDICT_NOTHING_FOUND:
            return 1;
        default:
            return 0;
    }
}

cl_error_t cli_scan_report_create(
    cl_scan_report_t **report_out,
    const struct cl_engine *engine)
{
    cl_scan_report_t *report;

    if (NULL == report_out)
        return CL_ENULLARG;

    *report_out = NULL;

    report = calloc(1, sizeof(*report));
    if (NULL == report)
        return CL_EMEM;

    report->version      = 1;
    report->status       = CL_SUCCESS;
    report->verdict      = CL_VERDICT_NOTHING_FOUND;
    report->completion   = CL_SCAN_COMPLETION_APPLICATION_ABORT;
    report->started_usec = report_now_usec();
    report->has_result   = false;

    report_get_engine_limit(engine, CL_ENGINE_MAX_FILESIZE, &report->limits.max_file_size);
    report_get_engine_limit(engine, CL_ENGINE_MAX_SCANSIZE, &report->limits.max_scan_size);
    report_get_engine_limit(engine, CL_ENGINE_PCRE_MAX_FILESIZE, &report->limits.max_pcre_file_size);
    report_get_engine_limit(engine, CL_ENGINE_MAX_MATCHER_WORK, &report->limits.max_matcher_work);
    report_get_engine_limit(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, &report->limits.max_temporary_size);
    report_get_engine_limit(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, &report->limits.max_contiguous_size);
    report_get_engine_limit(engine, CL_ENGINE_MAX_SCANTIME, &report->limits.max_scan_time);

    if (engine != NULL) {
        int status = CL_ERROR;
        long long value;

        value = cl_engine_get_num(engine, CL_ENGINE_MAX_FILES, &status);
        if (CL_SUCCESS == status && value >= 0)
            report->limits.max_files = (uint32_t)value;

        status = CL_ERROR;
        value  = cl_engine_get_num(engine, CL_ENGINE_MAX_RECURSION, &status);
        if (CL_SUCCESS == status && value >= 0)
            report->limits.max_recursion = (uint32_t)value;
    }

    *report_out = report;
    return CL_SUCCESS;
}

void cli_scan_report_set_root_size(
    cl_scan_report_t *report,
    uint64_t root_size)
{
    if (NULL != report)
        report->metrics.root_size = root_size;
}

void cli_scan_report_set_target(
    cl_scan_report_t *report,
    const char *target)
{
    if (NULL != report)
        report_replace_string(report, &report->target, target);
}

void cli_scan_report_set_fallback_details(
    cl_scan_report_t *report,
    uint64_t root_size,
    const cl_scan_report_limits_t *limits,
    const char *file_type,
    const char *reason)
{
    if (NULL == report)
        return;

    report->metrics.root_size            = root_size;
    report->metrics.skipped_operations  = 1;
    if (NULL != limits)
        report->limits = *limits;
    report_replace_string(report, &report->file_type, file_type);
    report_replace_string(report, &report->reason, reason);
}

void cli_scan_report_note_logical(
    cl_scan_report_t *report,
    uint64_t bytes,
    uint32_t recursion_depth)
{
    if (NULL == report)
        return;

    if (UINT64_MAX - report->metrics.logical_bytes < bytes)
        report->metrics.logical_bytes = UINT64_MAX;
    else
        report->metrics.logical_bytes += bytes;

    report_increment_u64(&report->metrics.files_scanned);
    if (recursion_depth > report->metrics.max_recursion_depth)
        report->metrics.max_recursion_depth = recursion_depth;
}

void cli_scan_report_note_matcher(
    cl_scan_report_t *report,
    uint64_t bytes)
{
    if (NULL == report)
        return;

    if (UINT64_MAX - report->metrics.matcher_bytes < bytes)
        report->metrics.matcher_bytes = UINT64_MAX;
    else
        report->metrics.matcher_bytes += bytes;
}

void cli_scan_report_note_contiguous(
    cl_scan_report_t *report,
    uint64_t bytes)
{
    if ((NULL != report) && (bytes > report->metrics.contiguous_bytes))
        report->metrics.contiguous_bytes = bytes;
}

void cli_scan_report_note_temporary(
    cl_scan_report_t *report,
    uint64_t bytes)
{
    if ((NULL != report) && (bytes > report->metrics.temporary_bytes))
        report->metrics.temporary_bytes = bytes;
}

void cli_scan_report_note_parser_operation(
    cl_scan_report_t *report)
{
    if (NULL != report)
        report_increment_u64(&report->metrics.parser_operations);
}

void cli_scan_report_note_detector_operation(
    cl_scan_report_t *report)
{
    if (NULL != report)
        report_increment_u64(&report->metrics.detector_operations);
}

void cli_scan_report_note_match_offset(
    cl_scan_report_t *report,
    uint64_t offset)
{
    if (NULL == report)
        return;

    report->pending_alert_offset       = offset;
    report->pending_alert_offset_valid = true;
}

bool cli_scan_report_take_match_offset(
    cl_scan_report_t *report,
    uint64_t *offset_out)
{
    bool present;

    if ((NULL == report) || (NULL == offset_out))
        return false;

    present = report->pending_alert_offset_valid;
    if (present)
        *offset_out = report->pending_alert_offset;
    report->pending_alert_offset_valid = false;
    return present;
}

void cli_scan_report_finish(
    cl_scan_report_t *report,
    const struct cli_ctx_tag *ctx,
    cl_error_t status,
    cl_verdict_t verdict,
    const char *last_alert)
{
    uint64_t finished_usec;
    const char *reason = NULL;

    if ((NULL == report) || report->finalized)
        return;

    if (NULL != ctx)
        reason = ctx->scan_incomplete_reason;

    /* A sticky incomplete marker is itself a required-operation failure. Do
     * not serialize a clean/trusted status alongside a non-complete outcome:
     * structured consumers must be able to reject the report without having
     * to infer a status from the human-readable reason. Preserve a more
     * specific caller status, but derive a non-clean status when older paths
     * supplied only the sticky context flag. Detection remains authoritative
     * and intentionally keeps its historical CL_SUCCESS status convention. */
    if ((NULL != ctx) && ctx->scan_incomplete &&
        (status == CL_SUCCESS || status == CL_VERIFIED) &&
        (verdict != CL_VERDICT_STRONG_INDICATOR) &&
        (verdict != CL_VERDICT_POTENTIALLY_UNWANTED)) {
        if ((ctx->limit_exceeded_result != CL_SUCCESS) &&
            (ctx->limit_exceeded_result != CL_VERIFIED))
            status = ctx->limit_exceeded_result;
        else if (ctx->abort_scan)
            status = CL_BREAK;
        else if (report_reason_is_unsupported(reason))
            status = CL_EUNPACK;
        else if (report_reason_contains(reason, "malformed") ||
                 report_reason_contains(reason, "truncated") ||
                 report_reason_contains(reason, "invalid") ||
                 report_reason_contains(reason, "broken") ||
                 report_reason_contains(reason, "could not be parsed"))
            status = CL_EPARSE;
        else
            status = CL_ERROR;
    }

    report->status  = status;
    report->verdict = verdict;

    /* Older callers may provide the terminal virus status without updating
     * the separate verdict field. Keep the versioned report self-consistent
     * so aggregation cannot emit a detected completion with a clean verdict. */
    if ((status == CL_VIRUS) &&
        (verdict != CL_VERDICT_STRONG_INDICATOR) &&
        (verdict != CL_VERDICT_POTENTIALLY_UNWANTED))
        report->verdict = CL_VERDICT_STRONG_INDICATOR;

    if (NULL != ctx) {
        report->metrics.skipped_operations = ctx->skipped_operations;
        /* Preserve the old manually-constructed cli_ctx contract for callers
         * that set only the sticky flag. */
        if (ctx->scan_incomplete && (report->metrics.skipped_operations == 0))
            report->metrics.skipped_operations = 1;
        report->metrics.matcher_bytes    = ctx->matcher_work;
        report->metrics.contiguous_bytes = ctx->contiguous_peak;
        report->metrics.temporary_bytes  = ctx->temporary_peak;

        if ((NULL != ctx->recursion_stack) &&
            (ctx->recursion_level < ctx->recursion_stack_size)) {
            const char *file_type = cli_ftname(ctx->recursion_stack[ctx->recursion_level].type);

            /* Match the public *_ex2 file_type_out contract for an unknown root. */
            if ((NULL == file_type) || (strcmp(file_type, "CL_TYPE_ANY") == 0))
                file_type = "CL_TYPE_BINARY_DATA";
            report_replace_string(report, &report->file_type, file_type);
        }
    }

    report_replace_string(report, &report->reason, reason);
    report_replace_string(report, &report->last_alert, last_alert);
    report->last_alert_offset_valid = false;
    if ((NULL != ctx) && (NULL != ctx->this_layer_evidence) &&
        (NULL != last_alert)) {
        uint64_t last_alert_offset;

        if (evidence_get_last_alert_offset(ctx->this_layer_evidence, &last_alert_offset)) {
            report->last_alert_offset       = last_alert_offset;
            report->last_alert_offset_valid = true;
        }
    }

    finished_usec = report_now_usec();
    if (finished_usec >= report->started_usec)
        report->metrics.elapsed_ms = (finished_usec - report->started_usec) / 1000ULL;

    /* A detection is still the authoritative terminal outcome when an
     * earlier optional/deep-parser path left a sticky incomplete marker. The
     * scan was not clean, and the report must not disguise the detection as a
     * parser/resource classification while the caller unwinds the remaining
     * bookkeeping. */
    if ((verdict == CL_VERDICT_STRONG_INDICATOR) ||
        (verdict == CL_VERDICT_POTENTIALLY_UNWANTED) ||
        (status == CL_VIRUS)) {
        report->completion = CL_SCAN_COMPLETION_DETECTION_TERMINATED;
    } else if ((status == CL_EMAXSIZE) ||
               (status == CL_EMAXFILES) ||
               (status == CL_EMAXREC) ||
               (status == CL_ETIMEOUT)) {
        report->completion = CL_SCAN_COMPLETION_LIMIT_INCOMPLETE;
    } else if (status == CL_ERESOURCE) {
        report->completion = CL_SCAN_COMPLETION_RESOURCE_FAILURE;
    } else if ((status == CL_BREAK) || ((NULL != ctx) && ctx->abort_scan)) {
        report->completion = CL_SCAN_COMPLETION_APPLICATION_ABORT;
    } else if ((NULL != ctx) && ctx->scan_incomplete) {
        if (ctx->limit_exceeded_result == CL_ERESOURCE) {
            report->completion = CL_SCAN_COMPLETION_RESOURCE_FAILURE;
        } else if ((status == CL_EMAXSIZE) ||
                   (status == CL_EMAXFILES) ||
                   (status == CL_EMAXREC) ||
                   (ctx->limit_exceeded)) {
            report->completion = CL_SCAN_COMPLETION_LIMIT_INCOMPLETE;
        } else if (report_status_is_operational_failure(status) ||
                   report_reason_contains(reason, "hash context could not be initialized") ||
                   report_reason_contains(reason, "hash digest could not be initialized")) {
            report->completion = CL_SCAN_COMPLETION_RESOURCE_FAILURE;
        } else if (report_reason_is_unsupported(reason)) {
            report->completion = CL_SCAN_COMPLETION_UNSUPPORTED;
        } else if (report_reason_contains(reason, "malformed") ||
                   report_reason_contains(reason, "truncated") ||
                   report_reason_contains(reason, "invalid") ||
                   report_reason_contains(reason, "broken") ||
                   report_reason_contains(reason, "could not be parsed")) {
            report->completion = CL_SCAN_COMPLETION_MALFORMED_CONFIRMED;
        } else {
            report->completion = CL_SCAN_COMPLETION_UNSUPPORTED;
        }
    } else if ((status == CL_EPARSE) || (status == CL_EFORMAT)) {
        report->completion = CL_SCAN_COMPLETION_MALFORMED_CONFIRMED;
    } else if ((status == CL_EUNPACK) ||
               (status == CL_EBYTECODE) ||
               (status == CL_EBYTECODE_TESTFAIL)) {
        /* These statuses identify an unsupported decoder/runtime boundary,
         * matching the daemon's bounded fallback report classification. */
        report->completion = CL_SCAN_COMPLETION_UNSUPPORTED;
    } else if (status != CL_SUCCESS) {
        report->completion = CL_SCAN_COMPLETION_RESOURCE_FAILURE;
    } else {
        report->completion = CL_SCAN_COMPLETION_COMPLETE;
    }

    /* Missing report metadata is itself a serialization failure. Preserve a
     * detection as authoritative, but never expose a clean/trusted or other
     * non-detection report whose required explanatory strings were lost. */
    if (report->string_allocation_failed &&
        report->completion != CL_SCAN_COMPLETION_DETECTION_TERMINATED) {
        report->status     = CL_EMEM;
        report->completion = CL_SCAN_COMPLETION_RESOURCE_FAILURE;
        if (report->metrics.skipped_operations != UINT64_MAX)
            report->metrics.skipped_operations++;
    }

    report->finalized  = true;
    report->has_result = true;
}

void cli_scan_report_note_post_scan_failure(
    cl_scan_report_t *report,
    cl_error_t status,
    const char *reason)
{
    if ((NULL == report) || (CL_SUCCESS == status))
        return;

    /* A detection remains authoritative. The caller still receives the
     * detection, while the public return path can preserve the stronger
     * virus result instead of replacing it with a cleanup error. */
    if ((report->verdict == CL_VERDICT_STRONG_INDICATOR) ||
        (report->verdict == CL_VERDICT_POTENTIALLY_UNWANTED) ||
        (report->status == CL_VIRUS) ||
        (report->completion == CL_SCAN_COMPLETION_DETECTION_TERMINATED))
        return;

    /* Preserve a more specific failure already produced by the scan. */
    if (report->completion != CL_SCAN_COMPLETION_COMPLETE)
        return;

    if (report->metrics.skipped_operations != UINT64_MAX)
        report->metrics.skipped_operations++;
    report->status     = status;
    report_replace_string(report, &report->reason, reason);
    report->completion = (status == CL_BREAK) ? CL_SCAN_COMPLETION_APPLICATION_ABORT
                                              : CL_SCAN_COMPLETION_RESOURCE_FAILURE;
    report->finalized  = true;
    report->has_result = true;
}

void cli_scan_report_merge(
    cl_scan_report_t *destination,
    const cl_scan_report_t *source)
{
    int destination_completion_rank;
    int source_completion_rank;
    bool replace_outcome;

    if ((NULL == destination) || (NULL == source) || destination->finalized)
        return;

    report_add_u64(&destination->metrics.root_size, source->metrics.root_size);
    report_add_u64(&destination->metrics.logical_bytes, source->metrics.logical_bytes);
    report_add_u64(&destination->metrics.matcher_bytes, source->metrics.matcher_bytes);
    if (source->metrics.contiguous_bytes > destination->metrics.contiguous_bytes)
        destination->metrics.contiguous_bytes = source->metrics.contiguous_bytes;
    if (source->metrics.temporary_bytes > destination->metrics.temporary_bytes)
        destination->metrics.temporary_bytes = source->metrics.temporary_bytes;
    report_add_u64(&destination->metrics.files_scanned, source->metrics.files_scanned);
    if (source->metrics.max_recursion_depth > destination->metrics.max_recursion_depth)
        destination->metrics.max_recursion_depth = source->metrics.max_recursion_depth;
    report_add_u64(&destination->metrics.elapsed_ms, source->metrics.elapsed_ms);
    report_add_u64(&destination->metrics.parser_operations, source->metrics.parser_operations);
    report_add_u64(&destination->metrics.detector_operations, source->metrics.detector_operations);
    report_add_u64(&destination->metrics.skipped_operations, source->metrics.skipped_operations);
    destination->string_allocation_failed |= source->string_allocation_failed;

    if (NULL == destination->target && NULL != source->target)
        report_replace_string(destination, &destination->target, source->target);
    if (NULL == destination->file_type && NULL != source->file_type) {
        report_replace_string(destination, &destination->file_type, source->file_type);
    } else if ((NULL != destination->file_type) && (NULL != source->file_type) &&
               strcmp(destination->file_type, source->file_type) != 0) {
        /* A directory has no single top-level file type. */
        free(destination->file_type);
        destination->file_type = NULL;
    }

    if (!destination->has_result) {
        destination->status     = source->status;
        destination->verdict    = source->verdict;
        destination->completion = source->completion;
        report_replace_string(destination, &destination->reason, source->reason);
        report_replace_string(destination, &destination->last_alert, source->last_alert);
        destination->last_alert_offset       = source->last_alert_offset;
        destination->last_alert_offset_valid = source->last_alert_offset_valid;
        destination->has_result = true;
        return;
    }

    destination_completion_rank = report_completion_rank(destination->completion);
    source_completion_rank      = report_completion_rank(source->completion);
    replace_outcome             = (source_completion_rank > destination_completion_rank) ||
                      ((source_completion_rank == destination_completion_rank) &&
                       (source->status != CL_SUCCESS) && (destination->status == CL_SUCCESS));

    if (replace_outcome) {
        destination->status     = source->status;
        destination->completion = source->completion;
        report_replace_string(destination, &destination->reason, source->reason);
        report_replace_string(destination, &destination->last_alert, source->last_alert);
        destination->last_alert_offset       = source->last_alert_offset;
        destination->last_alert_offset_valid = source->last_alert_offset_valid;
    } else if ((NULL == destination->reason) && (NULL != source->reason)) {
        report_replace_string(destination, &destination->reason, source->reason);
    }

    if (report_verdict_rank(source->verdict) > report_verdict_rank(destination->verdict)) {
        destination->verdict = source->verdict;
        if (source->completion == CL_SCAN_COMPLETION_DETECTION_TERMINATED) {
            report_replace_string(destination, &destination->last_alert, source->last_alert);
            destination->last_alert_offset       = source->last_alert_offset;
            destination->last_alert_offset_valid = source->last_alert_offset_valid;
        }
    }
}

void cl_scan_report_free(cl_scan_report_t *report)
{
    if (NULL == report)
        return;

    free(report->reason);
    free(report->last_alert);
    free(report->target);
    free(report->file_type);
    free(report);
}

cl_error_t cl_scan_report_get_status(
    const cl_scan_report_t *report,
    cl_error_t *status_out)
{
    if ((NULL == report) || (NULL == status_out))
        return CL_ENULLARG;

    *status_out = report->status;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_verdict(
    const cl_scan_report_t *report,
    cl_verdict_t *verdict_out)
{
    if ((NULL == report) || (NULL == verdict_out))
        return CL_ENULLARG;

    *verdict_out = report->verdict;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_completion(
    const cl_scan_report_t *report,
    cl_scan_completion_t *completion_out)
{
    if ((NULL == report) || (NULL == completion_out))
        return CL_ENULLARG;

    *completion_out = report->completion;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_metrics(
    const cl_scan_report_t *report,
    cl_scan_report_metrics_t *metrics_out)
{
    if ((NULL == report) || (NULL == metrics_out))
        return CL_ENULLARG;

    *metrics_out = report->metrics;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_limits(
    const cl_scan_report_t *report,
    cl_scan_report_limits_t *limits_out)
{
    if ((NULL == report) || (NULL == limits_out))
        return CL_ENULLARG;

    *limits_out = report->limits;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_reason(
    const cl_scan_report_t *report,
    const char **reason_out)
{
    if ((NULL == report) || (NULL == reason_out))
        return CL_ENULLARG;

    *reason_out = report->reason;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_last_alert(
    const cl_scan_report_t *report,
    const char **alert_out)
{
    if ((NULL == report) || (NULL == alert_out))
        return CL_ENULLARG;

    *alert_out = report->last_alert;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_last_alert_offset(
    const cl_scan_report_t *report,
    uint64_t *offset_out,
    bool *present_out)
{
    if ((NULL == report) || (NULL == offset_out) || (NULL == present_out))
        return CL_ENULLARG;

    *offset_out = report->last_alert_offset;
    *present_out = report->last_alert_offset_valid;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_target(
    const cl_scan_report_t *report,
    const char **target_out)
{
    if ((NULL == report) || (NULL == target_out))
        return CL_ENULLARG;

    *target_out = report->target;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_get_file_type(
    const cl_scan_report_t *report,
    const char **file_type_out)
{
    if ((NULL == report) || (NULL == file_type_out))
        return CL_ENULLARG;

    *file_type_out = report->file_type;
    return CL_SUCCESS;
}

cl_error_t cl_scan_report_to_json(
    const cl_scan_report_t *report,
    char **json_out)
{
    json_object *object;
    const char *serialized;
    cl_error_t status;

    if ((NULL == report) || (NULL == json_out))
        return CL_ENULLARG;

    *json_out = NULL;
    if (report->string_allocation_failed)
        return CL_EMEM;
    object    = json_object_new_object();
    if (NULL == object)
        return CL_EMEM;

    status = report_json_add_int(object, "version", (int)report->version);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_int(object, "status", (int)report->status);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_string(object, "status_name", cl_strerror(report->status));
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_int(object, "verdict", (int)report->verdict);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_string(object, "completion", report_completion_name(report->completion));
    if (CL_SUCCESS != status)
        goto json_error;
    if (NULL != report->target) {
        status = report_json_add_string(object, "target", report->target);
        if (CL_SUCCESS != status)
            goto json_error;
    }
    if (NULL != report->file_type) {
        status = report_json_add_string(object, "file_type", report->file_type);
        if (CL_SUCCESS != status)
            goto json_error;
    }
    status = report_json_add_u64(object, "root_size", report->metrics.root_size);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "logical_bytes", report->metrics.logical_bytes);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "matcher_bytes", report->metrics.matcher_bytes);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "contiguous_bytes", report->metrics.contiguous_bytes);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "temporary_bytes", report->metrics.temporary_bytes);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "files_scanned", report->metrics.files_scanned);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_recursion_depth", report->metrics.max_recursion_depth);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "elapsed_ms", report->metrics.elapsed_ms);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "parser_operations", report->metrics.parser_operations);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "detector_operations", report->metrics.detector_operations);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "skipped_operations", report->metrics.skipped_operations);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_file_size", report->limits.max_file_size);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_scan_size", report->limits.max_scan_size);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_pcre_file_size", report->limits.max_pcre_file_size);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_matcher_work", report->limits.max_matcher_work);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_temporary_size", report->limits.max_temporary_size);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_contiguous_size", report->limits.max_contiguous_size);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_scan_time", report->limits.max_scan_time);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_files", report->limits.max_files);
    if (CL_SUCCESS != status)
        goto json_error;
    status = report_json_add_u64(object, "max_recursion", report->limits.max_recursion);
    if (CL_SUCCESS != status)
        goto json_error;

    if (NULL != report->reason) {
        status = report_json_add_string(object, "reason", report->reason);
        if (CL_SUCCESS != status)
            goto json_error;
    }
    if (NULL != report->last_alert) {
        status = report_json_add_string(object, "last_alert", report->last_alert);
        if (CL_SUCCESS != status)
            goto json_error;
    }
    if (report->last_alert_offset_valid) {
        status = report_json_add_u64(object, "last_alert_offset", report->last_alert_offset);
        if (CL_SUCCESS != status)
            goto json_error;
    }

    serialized = json_object_to_json_string_ext(object, 0);
    if (NULL != serialized)
        *json_out = strdup(serialized);

    json_object_put(object);
    return (NULL != *json_out) ? CL_SUCCESS : CL_EMEM;

json_error:
    json_object_put(object);
    return status;
}
