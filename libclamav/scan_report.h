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

    cl_scan_report_metrics_t metrics;
    cl_scan_report_limits_t limits;

    uint64_t started_usec;
    bool finalized;
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

void cli_scan_report_finish(
    cl_scan_report_t *report,
    const struct cli_ctx_tag *ctx,
    cl_error_t status,
    cl_verdict_t verdict,
    const char *last_alert);

#endif /* __SCAN_REPORT_H_LC */
