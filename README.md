# NginxConfigGuard

Read-only, offline review of one explicitly named local Nginx configuration file.
A new byte lexer builds a nested AST and models HTTP scope inheritance, ordered
`set` assignments, conservative `if` branch joins and lazy literal `map` output.
Four selected policies produce private, position-only JSON. Runtime dependencies
are Python's standard library only.

This independent AI-assisted implementation does not import, rename, wrap or run
Gixy-Next. Its selected source/rule reference, fixed revision, complete selected
module audit and attribution are recorded in [ORIGIN](ORIGIN.md).

## Run

```sh
python -m pip install .
nginx-config-guard /path/to/nginx.conf
python -m nginx_config_guard /path/to/nginx.conf
```

Python 3.11+. Exactly one local regular file is read into an immutable snapshot.
The tool emits JSON on stdout and never modifies input, writes report/config files,
executes Nginx/plugins/Lua/Perl, starts processes, accesses the network, resolves DNS
or sends requests. URL/stdin/@list/directory discovery are unsupported.

Exit 0: PASS within the four stated static policies; exit 1: FAIL for a demonstrated
policy pattern; exit 2: OPEN for partial, unsupported or review-requiring input.
FAIL takes priority when an OPEN also exists. `parse_complete`, `coverage_complete`
and individual `selected_rules` state the practical scope. Every report preserves
`deployment_security`, `nginx_configuration_validity` and `application_eligibility`
as **OPEN**, including policy PASS. No incident, exploitable request, actual
unauthorized response, DNS destination safety or provider approval is established.

## Four frozen policies

| Policy | Understood behavior | OPEN boundary |
| --- | --- | --- |
| `alias_mapping` | Direct absolute literal alias in static prefix/`^~`/exact location. Prefix replacement concatenates the unmatched suffix. A missing prefix slash with slash-ended alias fails the component-boundary policy; a slash-ended directory prefix with no alias separator fails the sibling-name policy. Exact locations do not concatenate an unmatched URI suffix. | Both slashes missing have ambiguous file/directory intent. Inherited, regex, named, variable, non-absolute and backslash-containing alias paths remain OPEN. No filesystem contents or path payloads are emitted/read. |
| `allow_without_deny` | Address rules keep source order. Any local allow/deny declaration replaces the complete inherited list; otherwise HTTP/server/location/limit_except scopes inherit it. Numeric IPv4/IPv6/CIDR, `unix:` and `all` are recognized. A selective allow list needs a first terminal `deny all`; a specific deny does not protect every unmatched client. `allow all` alone is treated as an intentional public scope. | Unknown addresses/arity are OPEN. `satisfy any` with enabled inherited `auth_basic`/`auth_request` keeps alternative authentication intent OPEN; nearest `off` overrides the parent. Other auth modules are outside this profile. No IP allowlist intent or authentication result is inferred. |
| `return_access_phase` | Recognizes return in server/location and conditional scope, address rules and enabled `auth_basic`/`auth_request` controls. A server return precedes location address/auth checks. A 0-399 status or supported redirect URL with such controls fails the phase-conflict policy. | Conditional returns, internal/named locations, method-selected controls and error/444 returns retain OPEN because intent/reachability is unknown. `return` without restrictive address/auth controls is not a conflict. Redirecting `rewrite` is explicitly outside this first rule; rewrite control flow is OPEN. |
| `untrusted_proxy_destination` | Splits `$name`/`${name}`/`$1` script parts without evaluating code. HTTP server then selected location assignments run in rewrite order before proxy content regardless of proxy declaration order. Literal maps union all possible outputs and require one explicit default; variable-valued outputs propagate provenance. Maps cache their first evaluation, including nested lookup-source evaluation and branch-dependent nested-cache joins. Later dependency assignments cannot make a cached untrusted value look finite. Symbolic protocol/authority/URI boundaries survive transit through set and map outputs. Fixed finite values can bound a target despite an untrusted lookup key. Request headers/arguments/cookies/host/URI/body/client-address/captures are untrusted sources; unknown variables stay OPEN. Scheme has finite HTTP/HTTPS values. Only protocol/authority before a literal slash boundary participates in target control; variables after a fixed `/` do not select an authority. | Regex/options/duplicate/defaultless maps, lazy cycles, protected-builtin assignments, unknown variable providers, malformed/static UNIX-socket authorities, rewrite routing and inherited/nested location execution stay OPEN. Auth or internal routing does not prove a destination safe. Finite destinations mean configured bounded strings, not an approved network allowlist. |

The static proxy rule checks configured target provenance. It does not prove that
a directive is reachable, distinguish every cached-map first use from ancillary
modules, or model real network requests. Conditional variable paths are joined;
other control effects remain OPEN. Top-level location selection helper understands
case-sensitive exact match, longest prefix and `^~` suppression of regex search for
an already normalized URI. Regex/dynamic/named candidates and nested location
routing are inventoried with OPEN; PCRE is never compiled or executed. OS-specific
case folding, URI normalization, internal redirects and full Nginx module grammar
are outside this profile.

Ancillary recognized directives (for example listen/server_name/root/index/logs,
resolver/proxy headers/timeouts and worker settings) are parsed as AST values and
not security-reviewed. Their full argument semantics are not validated. Unknown
HTTP directives/blocks and malformed selected contexts cannot produce a clean
result. Streams and standalone configuration fragments are outside the required
single-HTTP-block profile. All other Gixy security/performance plugins are marked
UNIMPLEMENTED; this does not claim all Gixy rules or CLI/API compatibility.

## Include and privacy contract

**This first version never expands any include.** Every include, including those
inside a map, marks coverage OPEN. Literal, glob, dynamic, self/mutual-cycle and
symlink targets are all left unread. There is no authorized-root/include feature,
no glob traversal, no recursive file byte budget to bypass and no background read
of files named by alias/auth/log/resolver directives.

Reports expose fixed rule/diagnostic labels, numeric source scope IDs, byte offsets,
line/byte-column positions, counts, size and snapshot SHA-256 only. They omit source
paths, arbitrary directive/variable/map names, addresses, regex text, arguments,
credentials, response bodies and raw exception text. The fingerprint is evidence
identity, not anonymization. Final input path-component symlinks are rejected with
`O_NOFOLLOW` where available; parent path components follow normal OS resolution.
Size/time identity and full length are checked before and after reading.

Default hard limits: 1 MiB input, 50,000 tokens, 4,096 physical bytes per token or
expanded value, 128 directive arguments, 10,000 AST nodes, 256 inventoried HTTP
scopes, 32 levels of nesting/variable resolution, 512 scoped variables, 16 finite
alternatives, 256 map entries, 50,000 model steps, 200 findings and 128 KiB JSON.
The library `Limits` argument can tighten these; it cannot raise the defaults.
Wrong types raise TypeError and invalid values ValueError. Budget exhaustion,
parse failures and report reduction retain explicit OPEN and positions. A reduced
report preserves the first recorded FAIL.

## Verification and references

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python -m build
```

[VALIDATION](VALIDATION.md) and `evidence/` record the actual source and independent
installed-consumer checks; [DEFENSIVE_SCOPE](DEFENSIVE_SCOPE.md) limits use and claims.
Complete new MIT and unchanged upstream MPL notice text are retained in both
packages. No upstream runtime implementation is distributed or relicensed.

Primary syntax/semantic references: [Nginx core location/alias](https://nginx.org/en/docs/http/ngx_http_core_module.html),
[access inheritance/order](https://nginx.org/en/docs/http/ngx_http_access_module.html),
[rewrite phases/set/return](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html),
[proxy target](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass),
[lazy map](https://nginx.org/en/docs/http/ngx_http_map_module.html), and
[Nginx 1.28.0 token lexer](https://github.com/nginx/nginx/blob/release-1.28.0/src/core/ngx_conf_file.c#L472).
The last reference informed whitespace, comment, quote, backslash and variable
brace behavior. Additional selected Nginx 1.28.0 URL/proxy source paths were checked
for URI boundaries. IPv4/name URLs accept a question mark before a slash, while the
bracketed IPv6 parser has a different boundary grammar; this strict first profile
conservatively keeps any question/fragment mark before a literal slash OPEN. It
does not substitute urllib URL behavior for Nginx parsing. These are partial
source references, not a complete Nginx audit.
