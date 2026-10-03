## Current version 0.1.2: attribution and bounded verification, 2026-10-03

New implementation author and maintainer: dhtfish98. Package version: `0.1.2`.

Required local file-open capabilities now fail closed to controlled OPEN before reading; missing, zero, None, boolean, string and floating-point flag values are covered by API/CLI regression contrasts. Normal regular files and symlink/FIFO rejection remain covered.

The current source suite passes 55 tests on Python 3.14/macOS arm64. Final wheel and sdist are built from the final files. A fresh consumer installation also passes 55 tests. Installed/source/wheel runtime bytes, licenses, retained upstream notices, RECORD and command contracts are verified separately before publication. Exact package hashes and execution receipts are recorded externally rather than embedded in this self-referential document.

These tests verify the documented finite profile. Historical native/reference measurements below are preserved; they are not new runs for this revision. Matching remote CI, actual deployments, applicant identity and CVP approval remain OPEN until separately evidenced.

## Prior verification evidence

# Validation record

## Version 0.1.1 omission review, 2026-10-03 (Asia/Tokyo)

The review reproduced two defects in version 0.1.0: a first alias-policy FAIL
arriving at the last finding slot was discarded from the global verdict, and
argparse errors echoed arbitrary caller arguments. Version 0.1.1 retains the
first demonstrated failure with its supporting position under finding/report
caps and returns private JSON OPEN for argument errors.

The 54 local source tests and the same 54 tests against a fresh offline wheel
installation pass. New regressions exercise both the default 200-finding cap
and a lower cap of two, preservation of an earlier FAIL, invalid argument privacy,
CLI exit codes and unchanged input bytes. The final source/wheel/installed modules,
complete retained notices and sdist source bytes are checked independently.
Matching hosted CI and publication for this revision require separate verification
after the final commit; this local record does not establish that outcome.

## Original version 0.1.0 local observations

Local validation date: 2026-10-02 (Asia/Tokyo). Machine-readable evidence records
source test count, actual interpreter/platform, independently installed CLI,
input hashes/immutability and package source/full-notice identity. Final artifact
hashes are stored in the external engineering handoff, avoiding circular package
self-hash claims. Source-review evidence lists every new runtime/test/package/CI,
document and notice file actually read; upstream review is selected modules only.

Targeted inert fixtures cover quote/escape/comment/variable-brace lexer behavior,
real AST/scope inheritance, four alias slash combinations and exact/regex/dynamic
counterexamples, complete local access-list replacement and ordered deny behavior,
return/access/auth/server/conditional/internal/method contexts, proxy protocol and
literal URI boundaries, sequential/transitive/sibling set provenance, finite lazy
map outputs/defaults/cycles/first-use caching, context/shape errors and every budget.
Include self/mutual/glob/symlink/dynamic targets are proven unread; input files remain
unchanged. Paths/private arguments/identifiers/exception text are absent from JSON.
Mocks forbid network and process calls. Legacy execution/output/plugin flags fail.

Fresh offline wheel installation uses no dependencies/PYTHONPATH and runs from
outside the source tree. Runtime source bytes are checked against both the reviewed
source and installed modules; wheel/sdist contain complete new MIT and unchanged
upstream MPL notice bytes plus provenance/scope/validation. Sdist retains source,
tests, package/CI definitions and review evidence without local environments/caches.

No actual Nginx parser/server, HTTP traffic, filesystem alias target or auth provider
was executed. CI is defined for Python 3.11/3.14; hosted CI was not run in this task.
Only the actual local CPython/platform recorded in evidence was executed. All
Nginx validity, deployment security, other-plugin completeness and CVP eligibility
claims remain bounded or OPEN as described in README.
