# Brief 32 GiB Status Summary

The implementation at commit
`5becea1236d466ee21f9bd5d3bcd0595ebc1460b` passed the Release suite,
1,284 `libclamav` checks, all 63 Rust tests, all six Valgrind suites, and a
fresh ten-suite ASan/UBSan build. Release and sanitizer exact-32-GiB gates
verified all boundary offsets, rejected 32 GiB + 1, passed cancellation, and
passed exact-edge concurrency with 1, 2, and 4 workers. A private `clamd`
instance detected the end-of-file marker at offset `34359738304`, while
`clamdscan --stream` refused an oversized regular file rather than sending a
truncated prefix.

That implementation is ready for review as a bounded sparse raw-scan release
candidate, but it is not yet production-certified. Remaining qualification
work is an exact-edge clamd INSTREAM transfer, real milter protocol integration,
production CVD/custom-database and adversarial deep-parser/cold-cache testing,
and an attested run on the labelled GitHub release runner. The pending
sanitizer-workflow update builds milter and leaves non-instrumented Rust and
Valgrind suites in the Release test path; it passed local controls but has not
yet been exercised by GitHub Actions. The follow-on documentation/workflow
commit does not claim a rerun of the full remote matrix at its new HEAD.
