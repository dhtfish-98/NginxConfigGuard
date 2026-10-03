# Origin and honest attribution

Rule/structure reference: [MegaManSec/Gixy-Next](https://github.com/MegaManSec/Gixy-Next/tree/a94d1fcedcfcb30f16011fba40c6dab8940f0592),
fixed commit `a94d1fcedcfcb30f16011fba40c6dab8940f0592`. Complete selected own modules
were read: parser/raw_parser and nginx_parser, directives/block and directive,
context, variable, builtin_variables, utils, manager, plugin dispatcher/base,
selected alias_traversal, allow_without_deny, return_bypasses_allow_deny and ssrf,
regex_redos removal path, exception/diagnostic/issue types, CLI/parser/config entry
and import modules. Exact paths/hashes/line counts are in upstream-review evidence.
The rest of the plugin collection, formatters, test repository and third-party
crossplane/regex/tldextract/build/CI implementation sources were not fully audited.

The upstream raw parser delegates tokenization to crossplane and may create a
configuration tempfile. Its parser resolves local include globs with active-stack
cycle protection, without this new project's no-include contract. Context and
variable classes propagate provider/regex dependencies. Dynamic plugin imports,
custom variable drop-in file reads, recursive rule dispatch, output/config-file
writes and `regex_redos.py:120` HTTP POST/Recheck are excluded from the new runtime.
No external Recheck request, active target probe or Lua/Perl/plugin execution path
exists in NginxConfigGuard.

New implementation author and maintainer: dhtfish98. It contains no
renamed, copied, imported or wrapped Gixy runtime. The substantive new contribution
is an explicit bounded byte lexer and AST, position-only private reports, actual
HTTP scope/list inheritance, ordered rewrite assignment and branch joins, lazy
finite map provenance/cache, protocol/authority boundaries, four frozen defensive
policies, unknown propagation and targeted regression tests. Complete upstream
compatibility and complete Nginx semantics are explicitly excluded.

Gixy-Next is a source/design reference only; its implementation, tests and data
are not redistributed. The unused reference-only MPL license copy was removed.
The new implementation remains MIT under LICENSE. This does not change the
upstream project's licensing or authorship; its fixed source link above remains.

The attribution to dhtfish98 applies to this new implementation and its maintenance.
Original source authors and licenses remain attributed separately. This record
does not establish authorship of Gixy-Next/Nginx, whole-suite rewriting,
a proven deployment incident or application approval. Eligibility remains OPEN.
