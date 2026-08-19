/*
 * Structured scan reports.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "scan_report.h"

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

static void report_replace_string(char **destination, const char *value)
{
    char *copy = report_strdup(value);

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

    report->version    = 1;
    report->status     = CL_SUCCESS;
    report->verdict    = CL_VERDICT_NOTHING_FOUND;
    report->completion = CL_SCAN_COMPLETION_APPLICATION_ABORT;
    report->started_usec = report_now_usec();

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
        report_replace_string(&report->target, target);
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

    report->metrics.files_scanned++;
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
        report->metrics.parser_operations++;
}

void cli_scan_report_note_detector_operation(
    cl_scan_report_t *report)
{
    if (NULL != report)
        report->metrics.detector_operations++;
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

    report->status  = status;
    report->verdict = verdict;

    if (NULL != ctx) {
        reason = ctx->scan_incomplete_reason;
        report->metrics.skipped_operations = ctx->scan_incomplete ? 1 : 0;
        report->metrics.matcher_bytes = ctx->matcher_work;
        report->metrics.contiguous_bytes = ctx->contiguous_peak;
        report->metrics.temporary_bytes = ctx->temporary_peak;

        if ((NULL != ctx->recursion_stack) &&
            (ctx->recursion_level < ctx->recursion_stack_size)) {
            const char *file_type = cli_ftname(ctx->recursion_stack[ctx->recursion_level].type);

            /* Match the public *_ex2 file_type_out contract for an unknown root. */
            if ((NULL == file_type) || (strcmp(file_type, "CL_TYPE_ANY") == 0))
                file_type = "CL_TYPE_BINARY_DATA";
            report_replace_string(&report->file_type, file_type);
        }
    }

    report_replace_string(&report->reason, reason);
    report_replace_string(&report->last_alert, last_alert);

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
        if ((status == CL_EMAXSIZE) ||
            (status == CL_EMAXFILES) ||
            (status == CL_EMAXREC) ||
            (ctx->limit_exceeded)) {
            report->completion = CL_SCAN_COMPLETION_LIMIT_INCOMPLETE;
        } else if (report_status_is_operational_failure(status)) {
            report->completion = CL_SCAN_COMPLETION_RESOURCE_FAILURE;
        } else if (report_reason_contains(reason, "unsupported") ||
                   report_reason_contains(reason, "not implemented") ||
                   report_reason_contains(reason, "requires")) {
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
    } else if (status != CL_SUCCESS) {
        report->completion = CL_SCAN_COMPLETION_RESOURCE_FAILURE;
    } else {
        report->completion = CL_SCAN_COMPLETION_COMPLETE;
    }

    report->finalized = true;
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

    if ((NULL == report) || (NULL == json_out))
        return CL_ENULLARG;

    *json_out = NULL;
    object    = json_object_new_object();
    if (NULL == object)
        return CL_EMEM;

    json_object_object_add(object, "version", json_object_new_int((int)report->version));
    json_object_object_add(object, "status", json_object_new_int((int)report->status));
    json_object_object_add(object, "status_name", json_object_new_string(cl_strerror(report->status)));
    json_object_object_add(object, "verdict", json_object_new_int((int)report->verdict));
    json_object_object_add(object, "completion", json_object_new_string(report_completion_name(report->completion)));
    if (NULL != report->target)
        json_object_object_add(object, "target", json_object_new_string(report->target));
    if (NULL != report->file_type)
        json_object_object_add(object, "file_type", json_object_new_string(report->file_type));
    json_object_object_add(object, "root_size", json_object_new_int64((int64_t)report->metrics.root_size));
    json_object_object_add(object, "logical_bytes", json_object_new_int64((int64_t)report->metrics.logical_bytes));
    json_object_object_add(object, "matcher_bytes", json_object_new_int64((int64_t)report->metrics.matcher_bytes));
    json_object_object_add(object, "contiguous_bytes", json_object_new_int64((int64_t)report->metrics.contiguous_bytes));
    json_object_object_add(object, "temporary_bytes", json_object_new_int64((int64_t)report->metrics.temporary_bytes));
    json_object_object_add(object, "files_scanned", json_object_new_int64((int64_t)report->metrics.files_scanned));
    json_object_object_add(object, "max_recursion_depth", json_object_new_int((int)report->metrics.max_recursion_depth));
    json_object_object_add(object, "elapsed_ms", json_object_new_int64((int64_t)report->metrics.elapsed_ms));
    json_object_object_add(object, "parser_operations", json_object_new_int64((int64_t)report->metrics.parser_operations));
    json_object_object_add(object, "detector_operations", json_object_new_int64((int64_t)report->metrics.detector_operations));
    json_object_object_add(object, "skipped_operations", json_object_new_int64((int64_t)report->metrics.skipped_operations));
    json_object_object_add(object, "max_file_size", json_object_new_int64((int64_t)report->limits.max_file_size));
    json_object_object_add(object, "max_scan_size", json_object_new_int64((int64_t)report->limits.max_scan_size));
    json_object_object_add(object, "max_pcre_file_size", json_object_new_int64((int64_t)report->limits.max_pcre_file_size));
    json_object_object_add(object, "max_matcher_work", json_object_new_int64((int64_t)report->limits.max_matcher_work));
    json_object_object_add(object, "max_temporary_size", json_object_new_int64((int64_t)report->limits.max_temporary_size));
    json_object_object_add(object, "max_contiguous_size", json_object_new_int64((int64_t)report->limits.max_contiguous_size));
    json_object_object_add(object, "max_scan_time", json_object_new_int64((int64_t)report->limits.max_scan_time));
    json_object_object_add(object, "max_files", json_object_new_int((int)report->limits.max_files));
    json_object_object_add(object, "max_recursion", json_object_new_int((int)report->limits.max_recursion));

    if (NULL != report->reason)
        json_object_object_add(object, "reason", json_object_new_string(report->reason));
    if (NULL != report->last_alert)
        json_object_object_add(object, "last_alert", json_object_new_string(report->last_alert));

    serialized = json_object_to_json_string_ext(object, 0);
    if (NULL != serialized)
        *json_out = strdup(serialized);

    json_object_put(object);
    return (NULL != *json_out) ? CL_SUCCESS : CL_EMEM;
}
