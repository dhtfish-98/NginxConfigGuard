> v0.1.5 的外部 Build 路径和已跟踪文件暂存须以本版本运行收据、GitHub Actions 和 Release 资产回验；以下 0.1.3 历史记录不自动验证新版本。

## Version 0.1.5: external build staging, 2026-10-08

This revision changes packaging/layout support and the version constant. The six
other runtime modules remain byte-identical to the v0.1.4 public baseline
`6366317e7817e121d981ed9e9fbd9714e76f3fac`. Documentation remains under
`项目文档`; staged source, caches, logs and distributions use an external central
Build directory.

The 72-test suite consists of 55 existing offline configuration checks and 17
build-layout checks. The latter cover tracked-only staging, source leaf/parent
links, restored tracked inputs and byte hashes, conflicting aliases, output
parent links, existing-stage refusal, source-contained Build paths, bounded
project names and linked project/cache directories. All fixtures are inert
temporary files owned by the test run. No external service is exercised.

Final source, sdist and isolated wheel-consumer results, interpreter versions,
installed module origins, file identities and asset hashes belong in external
receipts. Hosted main/tag CI and downloaded Release assets must be verified after
the final commit. No local test count establishes publication or CVP eligibility.
The builder requires caller-owned directories without concurrent modification;
it does not claim race-proof filesystem isolation against another process.

## Historical version 0.1.3: applicable material notices, 2026-10-03

New implementation author and maintainer: dhtfish98. Package version: `0.1.3`.

This revision removes 1 unused reference-only license/notice copies and reconciles current material provenance and packaging. Actual embedded third-party data, converted vectors, frozen test-oracle source, applicable licenses and the scoped Redis patch/terms remain unchanged where present. The project's own LICENSE is unchanged. Runtime behavior is unchanged; only its version constant advances.

The current source suite passes 55 tests on Python 3.14/macOS arm64. Publication gates also require the same nonzero suite on a fresh wheel consumer and an independent consumer of a wheel rebuilt offline from the source archive. Separate receipts bind actual outcomes, installed origins, runtime/data/license bytes, wheel RECORD, CLI contracts and exact artifact hashes; no self-referential package hash is embedded here.

Historical reference/native/oracle measurements below are retained as prior evidence and are not new measurements for this material-only revision. Current file identities are in SOURCE_MANIFEST.json. Matching remote CI/publication, deployment security, applicant identity and CVP approval require separate evidence and remain OPEN here.

## Prior verification evidence

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
