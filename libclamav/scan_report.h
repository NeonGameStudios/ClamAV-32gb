/*
 * Internal implementation of the public structured scan report API.
 */

#ifndef __SCAN_REPORT_H_LC
#define __SCAN_REPORT_H_LC

#include <stdbool.h>
#include <stdint.h>

#include "clamav.h"

struct cl_engine;
struct cli_ctx_tag;

struct cl_scan_report {
    uint32_t version;
    cl_error_t status;
    cl_verdict_t verdict;
    cl_scan_completion_t completion;

    char *reason;
    char *last_alert;
    char *target;
    char *file_type;

    uint64_t pending_alert_offset;
    uint64_t last_alert_offset;
    bool pending_alert_offset_valid;
    bool last_alert_offset_valid;

    cl_scan_report_metrics_t metrics;
    cl_scan_report_limits_t limits;

    uint64_t started_usec;
    bool finalized;
    bool has_result;
    bool string_allocation_failed;
};

cl_error_t cli_scan_report_create(
    cl_scan_report_t **report_out,
    const struct cl_engine *engine);

void cli_scan_report_set_root_size(
    cl_scan_report_t *report,
    uint64_t root_size);

void cli_scan_report_set_target(
    cl_scan_report_t *report,
    const char *target);

/* Add the input and policy details for a client-side failure that happened
 * before libclamav received a scan context. */
void cli_scan_report_set_fallback_details(
    cl_scan_report_t *report,
    uint64_t root_size,
    const cl_scan_report_limits_t *limits,
    const char *file_type,
    const char *reason);

void cli_scan_report_note_logical(
    cl_scan_report_t *report,
    uint64_t bytes,
    uint32_t recursion_depth);

void cli_scan_report_note_matcher(
    cl_scan_report_t *report,
    uint64_t bytes);

void cli_scan_report_note_contiguous(
    cl_scan_report_t *report,
    uint64_t bytes);

void cli_scan_report_note_temporary(
    cl_scan_report_t *report,
    uint64_t bytes);

void cli_scan_report_note_parser_operation(
    cl_scan_report_t *report);

void cli_scan_report_note_detector_operation(
    cl_scan_report_t *report);

/* Matchers may provide a native-width coordinate before appending an alert.
 * The offset is committed to the report only when the retained last alert is
 * a root-level native matcher result. */
void cli_scan_report_note_match_offset(
    cl_scan_report_t *report,
    uint64_t offset);

bool cli_scan_report_take_match_offset(
    cl_scan_report_t *report,
    uint64_t *offset_out);

void cli_scan_report_finish(
    cl_scan_report_t *report,
    const struct cli_ctx_tag *ctx,
    cl_error_t status,
    cl_verdict_t verdict,
    const char *last_alert);

/* Record an I/O failure discovered after the scan itself finalized, such as
 * failure closing a descriptor owned by a public convenience API. */
void cli_scan_report_note_post_scan_failure(
    cl_scan_report_t *report,
    cl_error_t status,
    const char *reason);

/* Combine finalized child reports for front ends that walk a directory.  The
 * destination remains mutable and is finalized by the owning front end when
 * the request ends. */
void cli_scan_report_merge(
    cl_scan_report_t *destination,
    const cl_scan_report_t *source);

#endif /* __SCAN_REPORT_H_LC */
