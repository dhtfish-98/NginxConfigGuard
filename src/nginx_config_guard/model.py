"""HTTP scopes, ordered rewrite assignments and bounded destination provenance."""
from dataclasses import dataclass
import ipaddress
from urllib.parse import urlsplit

from .parser import location_kind

AUTH = ('auth_basic', 'auth_request')
REQUEST_NAMES = frozenset(('host', 'request_uri', 'uri', 'document_uri', 'args', 'query_string',
                           'request', 'request_body', 'remote_addr', 'remote_user'))
REQUEST_PREFIXES = ('http_', 'arg_', 'cookie_', 'upstream_http_', 'proxy_protocol_')
SCOPES = frozenset(('http', 'server', 'location', 'if', 'limit_except'))
IGNORED = {'worker_processes', 'worker_connections', 'pid', 'error_log', 'access_log', 'listen',
           'server_name', 'root', 'index', 'resolver', 'auth_basic_user_file', 'proxy_set_header',
           'proxy_read_timeout', 'proxy_connect_timeout', 'proxy_send_timeout', 'default_type',
           'sendfile', 'keepalive_timeout', 'charset', 'server_tokens'}
BLOCK_CONTEXT = {'http': {'main'}, 'events': {'main'}, 'upstream': {'http'}, 'types': {'http', 'server', 'location'},
                 'server': {'http'}, 'location': {'server', 'location'}, 'if': {'server', 'location'},
                 'limit_except': {'location'}, 'map': {'http'}}
DIRECT_CONTEXT = {'alias': {'location'}, 'allow': {'http', 'server', 'location', 'limit_except'},
                  'deny': {'http', 'server', 'location', 'limit_except'}, 'set': {'server', 'location', 'if'},
                  'return': {'server', 'location', 'if'}, 'proxy_pass': {'location', 'if', 'limit_except'},
                  'satisfy': {'http', 'server', 'location'}, 'auth_basic': {'http', 'server', 'location', 'limit_except'},
                  'auth_request': {'http', 'server', 'location'}, 'internal': {'location'},
                  'rewrite': {'server', 'location', 'if'}, 'break': {'server', 'location', 'if'}}
ARITY = {'alias': (1, 1), 'allow': (1, 1), 'deny': (1, 1), 'set': (2, 2), 'return': (1, 2),
         'proxy_pass': (1, 1), 'satisfy': (1, 1), 'auth_basic': (1, 1), 'auth_request': (1, 1),
         'internal': (0, 0), 'rewrite': (2, 3), 'break': (0, 0), 'include': (1, 1)}


@dataclass(frozen=True)
class Value:
    kind: str
    options: tuple[str, ...] = ()
    providers: tuple = ()
    forms: tuple = ()


def variables(text):
    """Literal/variable script parts, including ${name}; never executes text."""
    parts, literal, i = [], [], 0
    while i < len(text):
        if text[i] != '$':
            literal.append(text[i]); i += 1; continue
        if literal:
            parts.append(('literal', ''.join(literal))); literal = []
        i += 1
        if i < len(text) and text[i] == '{':
            end = text.find('}', i + 1)
            if end < 0:
                return None
            name = text[i + 1:end]; i = end + 1
        elif i < len(text) and text[i] in '123456789':
            name = text[i]; i += 1
        else:
            begin = i
            while i < len(text) and (text[i].isascii() and (text[i].isalnum() or text[i] == '_')):
                i += 1
            name = text[begin:i]
        if not name or not all(c.isascii() and (c.isalnum() or c == '_') for c in name):
            return None
        parts.append(('variable', name.lower()))
    if literal:
        parts.append(('literal', ''.join(literal)))
    return parts


def destination_name(text):
    parts = variables(text)
    return parts[0][1] if parts and len(parts) == 1 and parts[0][0] == 'variable' else None


def merge(a, b, report, node):
    providers = (a.providers + b.providers)[:8]
    if a.kind != 'finite' or b.kind != 'finite':
        def forms(value):
            if value.kind == 'finite':
                return tuple((Value('finite', (x,), value.providers),) for x in value.options)
            return value.forms or ((Value(value.kind, providers=value.providers),),)
        alternatives = forms(a) + forms(b)
        if len(alternatives) > report.limits.alternatives:
            report.stop('alternative_limit', 'Symbolic branch budget exhausted.', node)
        kind = 'untrusted' if 'untrusted' in (a.kind, b.kind) else 'unknown'
        return Value(kind, providers=providers, forms=alternatives)
    choices = tuple(sorted(set(a.options + b.options)))
    if len(choices) > report.limits.alternatives:
        report.stop('alternative_limit', 'Variable finite-value budget exhausted.', node)
    return Value('finite', choices, providers)


class Model:
    def __init__(self, root, report):
        self.root, self.r, self.maps = root, report, {}

    def inherited(self, scope, name):
        current = scope
        while current:
            self.r.step(current)
            found = current.direct(name)
            if found:
                return found[-1]
            current = current.parent
        return None

    def access(self, scope):
        current = scope
        while current:
            self.r.step(current)
            rules = [n for n in current.children if n.name in ('allow', 'deny') and not n.block]
            if rules:
                return rules
            current = current.parent
        return []

    def structure(self, node):
        self.r.step(node)
        if node.name == 'map' and node.block:
            if node.parent.name != 'http' or len(node.args) != 2 or not destination_name(node.args[-1]):
                self.r.add('OPEN', 'map_header', 'Map provider is outside supported HTTP syntax.', node, incomplete=True)
                return
            dest = destination_name(node.args[-1])
            if dest in REQUEST_NAMES or dest.startswith(REQUEST_PREFIXES) or dest == 'scheme':
                self.r.add('OPEN', 'map_destination', 'Map destination is a protected builtin within this profile.', node, incomplete=True)
                self.maps[dest] = None
                return
            if dest in self.maps:
                self.maps[dest] = None
                self.r.add('OPEN', 'duplicate_variable_provider', 'Duplicate lazy map variable provider is ambiguous.', node, incomplete=True)
            else:
                self.maps[dest] = node
            if len(self.maps) > self.r.limits.variables:
                self.r.stop('variable_limit', 'Variable provider budget exhausted.', node)
            self.r.data['counts']['map_providers'] += 1
            if len(node.children) > self.r.limits.map_entries:
                self.r.stop('map_limit', 'Map entry budget exhausted.', node)
            entry_keys, defaults = set(), 0
            if variables(node.args[0]) is None:
                self.r.add('OPEN', 'map_source_script', 'Map source variable grammar is unresolved.', node, incomplete=True)
                self.maps[dest] = None
            for entry in node.children:
                if entry.name == 'include':
                    self.r.add('OPEN', 'include_unexpanded', 'Include is never expanded; external rules/provider values remain unknown.', entry, incomplete=True)
                elif entry.block or len(entry.args) != 1 or entry.name in ('hostnames', 'volatile') or entry.name.startswith('~'):
                    self.r.add('OPEN', 'map_entry_profile', 'Map entry/options/regex is outside literal-map grammar.', entry, incomplete=True)
                if entry.name.lower() in entry_keys:
                    self.r.add('OPEN', 'map_duplicate_key', 'Duplicate map keys are outside supported provider profile.', entry, incomplete=True)
                    self.maps[dest] = None
                entry_keys.add(entry.name.lower())
                defaults += entry.name == 'default'
            if defaults != 1:
                self.r.add('OPEN', 'map_default_profile', 'Literal-map profile requires exactly one explicit default.', node, incomplete=True)
            return  # Entry keys are data, never dispatch them as directives.
        if node is not self.root:
            if node.name == 'include':
                self.r.add('OPEN', 'include_unexpanded', 'Include is never expanded; no glob/path/file is read. Coverage is incomplete.', node, incomplete=True)
            elif node.block:
                allowed = BLOCK_CONTEXT.get(node.name)
                if allowed is None or node.parent.name not in allowed:
                    self.r.add('OPEN', 'unsupported_block', 'Unknown or unsupported block/context; semantics remain unknown.', node, incomplete=True)
                if node.name in ('http', 'events', 'server') and node.args:
                    self.r.add('OPEN', 'block_arguments', 'Unexpected arguments for selected block grammar.', node, incomplete=True)
                if node.name == 'upstream' and len(node.args) != 1:
                    self.r.add('OPEN', 'block_arguments', 'Upstream block requires one literal identifier in this profile.', node, incomplete=True)
                if node.name in SCOPES:
                    self.r.data['counts']['scopes'] += 1
                    if self.r.data['counts']['scopes'] > self.r.limits.scopes:
                        self.r.stop('scope_limit', 'Scope inventory budget exhausted.', node)
                    kind = location_kind(node)[0] if node.name == 'location' else None
                    self.r.data['scopes'].append({'id': node.identifier, 'kind': node.name,
                        'position': node.position(), 'location_kind': kind,
                        'parent_id': node.parent.identifier})
                    if node.name == 'location':
                        if kind not in ('prefix', 'high_prefix', 'exact') or '$' in location_kind(node)[1]:
                            self.r.add('OPEN', 'location_selection_unknown', 'Regex/named/dynamic/unknown location selection is not resolved.', node, incomplete=True)
                        if node.parent.name == 'location':
                            self.r.add('OPEN', 'nested_location_selection', 'Nested location routing/rewrite inheritance remains unknown.', node, incomplete=True)
                        if node.parent.name == 'location' and not location_kind(node)[1].startswith(location_kind(node.parent)[1]):
                            self.r.add('OPEN', 'nested_location_boundary', 'Nested static location is outside parent prefix profile.', node, incomplete=True)
                    if node.name == 'if':
                        self.r.add('OPEN', 'conditional_scope', 'If conditions are not evaluated; variable paths are joined conservatively.', node, incomplete=True)
                    if node.name == 'limit_except':
                        self.r.add('OPEN', 'method_subset', 'Method-selected access scope is inventoried; method reachability remains unknown.', node, incomplete=True)
            else:
                if node.name in ARITY and not ARITY[node.name][0] <= len(node.args) <= ARITY[node.name][1]:
                    self.r.add('OPEN', 'directive_arguments', 'Selected directive has unsupported argument count.', node, incomplete=True)
                elif node.name in DIRECT_CONTEXT and node.parent.name not in DIRECT_CONTEXT[node.name]:
                    self.r.add('OPEN', 'directive_context', 'Selected directive is outside supported Nginx context.', node, incomplete=True)
                elif node.name not in DIRECT_CONTEXT and node.name != 'include' and node.name not in IGNORED and node.parent.name not in ('events', 'upstream', 'types'):
                    self.r.add('OPEN', 'unsupported_directive', 'Directive semantics are outside the selected profile.', node, incomplete=True)
                if node.name in ('rewrite', 'break'):
                    self.r.add('OPEN', 'rewrite_control_flow', 'Rewrite/break routing effects are unsupported; later variable certainty is limited.', node, incomplete=True)
                if node.name in IGNORED and not node.args:
                    self.r.add('OPEN', 'directive_arguments', 'Recognized ancillary directive has no arguments.', node, incomplete=True)
                if node.name == 'satisfy' and node.args not in (('any',), ('all',)):
                    self.r.add('OPEN', 'satisfy_value', 'Satisfy value is outside any/all profile.', node, incomplete=True)
                if node.name == 'return' and node.args and not (node.args[0].isascii() and node.args[0].isdigit() and int(node.args[0]) <= 599) and not node.args[0].startswith(('http://', 'https://', '$scheme')):
                    self.r.add('OPEN', 'return_response_unknown', 'Return syntax is outside the selected status/URL profile.', node, incomplete=True)
                if node.name in ('alias', 'proxy_pass', 'satisfy', 'auth_basic', 'auth_request', 'internal') and len(node.parent.direct(node.name)) > 1:
                    self.r.add('OPEN', 'duplicate_single_directive', 'Duplicate single-value directive is ambiguous/invalid.', node, incomplete=True)
        for child in node.children:
            self.structure(child)
        if node.name == 'server':
            seen = set()
            for loc in [n for n in node.children if n.name == 'location' and n.block]:
                key = location_kind(loc)
                if key in seen:
                    self.r.add('OPEN', 'duplicate_location', 'Duplicate location selection is ambiguous/invalid.', loc, incomplete=True)
                seen.add(key)

    def resolve(self, name, env, stack, at):
        self.r.step(at)
        if name in env:
            return env[name]
        if name in stack or len(stack) >= self.r.limits.nesting:
            self.r.add('OPEN', 'variable_cycle', 'Lazy variable cycle/depth remains unresolved.', at, rule='untrusted_proxy_destination')
            return Value('unknown')
        if name in self.maps:
            node = self.maps[name]
            if node is None:
                return Value('unknown')
            # Lookup source is evaluated even when outputs are fixed literals;
            # its nested map first-use cache effects must remain observable.
            self.expression(node.args[0], env, stack + (name,), node)
            results, defaults, seen = None, 0, set()
            branches = []
            for entry in node.children:
                self.r.step(entry)
                if entry.block or len(entry.args) != 1 or entry.name in ('include', 'hostnames', 'volatile') or entry.name.startswith('~') or entry.name.lower() in seen:
                    self.r.add('OPEN', 'map_semantics_unknown', 'Map entries/options/regex or duplicate keys are outside literal-map profile.', entry, rule='untrusted_proxy_destination')
                    return Value('unknown', providers=(node,))
                seen.add(entry.name.lower())
                defaults += entry.name == 'default'
                branch_env = dict(env)
                result = self.expression(entry.args[0], branch_env, stack + (name,), entry)
                branches.append(branch_env)
                results = result if results is None else merge(results, result, self.r, entry)
            if defaults != 1 or results is None:
                self.r.add('OPEN', 'map_default_unknown', 'Explicit single default is required to prove bounded map output.', node, rule='untrusted_proxy_destination')
                return Value('unknown', providers=(node,))
            # Only the selected output expression executes in Nginx. Union
            # branch-specific cache effects; an unevaluated alternative cannot
            # be treated as a definitely cached constant on later first use.
            touched = set().union(*(set(branch) for branch in branches)) - set(env)
            for cached_name in touched:
                joined = branches[0].get(cached_name, Value('unknown'))
                for branch in branches[1:]:
                    joined = merge(joined, branch.get(cached_name, Value('unknown')), self.r, node)
                env[cached_name] = joined
            result = Value(results.kind, results.options, (node,) + results.providers[:7], results.forms)
            # Default Nginx maps are evaluated lazily and cache their first value.
            # A later set of an input dependency must not reclassify that cached
            # value as finite. Volatile maps are outside this profile.
            env[name] = result
            if len(env) > self.r.limits.variables:
                self.r.stop('variable_limit', 'Lazy evaluated variable budget exhausted.', node)
            return result
        if name == 'scheme':
            return Value('finite', ('http', 'https'))
        if name in REQUEST_NAMES or name.startswith(REQUEST_PREFIXES) or name in '123456789':
            return Value('untrusted')
        return Value('unknown')

    def extend_forms(self, candidates, value, at):
        if value.kind == 'finite':
            choices = tuple((Value('finite', (x,), value.providers),) for x in value.options)
        else:
            choices = value.forms or ((Value(value.kind, providers=value.providers),),)
        if len(candidates) * len(choices) > self.r.limits.alternatives:
            self.r.stop('alternative_limit', 'Symbolic template expansion budget exhausted.', at)
        expanded = []
        for candidate in candidates:
            for choice in choices:
                new = candidate
                for part in choice:
                    self.r.step(at)
                    if new and new[-1].kind == part.kind == 'finite':
                        text = new[-1].options[0] + part.options[0]
                        new = new[:-1] + (Value('finite', (text,), (new[-1].providers + part.providers)[:8]),)
                    else:
                        new += (part,)
                size = sum(len(p.options[0].encode()) if p.kind == 'finite' else 1 for p in new)
                if size > self.r.limits.token_bytes:
                    self.r.stop('expansion_bytes', 'Symbolic variable expansion budget exhausted.', at)
                expanded.append(new)
        return expanded

    def expression(self, text, env, stack, at):
        parts = variables(text)
        if parts is None:
            return Value('unknown', providers=(at,))
        choices, state, providers, forms = ('',), 'finite', (at,), [()]
        for kind, value in parts:
            self.r.step(at)
            abstract = Value('finite', (value,)) if kind == 'literal' else self.resolve(value, env, stack, at)
            forms = self.extend_forms(forms, abstract, at)
            providers = (providers + abstract.providers)[:8]
            if abstract.kind == 'untrusted':
                state = 'untrusted'
            elif abstract.kind == 'unknown' and state != 'untrusted':
                state = 'unknown'
            if abstract.kind == 'finite' and state == 'finite':
                if len(choices) * len(abstract.options) > self.r.limits.alternatives:
                    self.r.stop('alternative_limit', 'Finite template expansion budget exhausted.', at)
                choices = tuple(a + b for a in choices for b in abstract.options)
                if any(len(x.encode()) > self.r.limits.token_bytes for x in choices):
                    self.r.stop('expansion_bytes', 'Finite variable expansion byte budget exhausted.', at)
        return Value(state, choices if state == 'finite' else (), providers, tuple(forms) if state != 'finite' else ())

    def assignments(self, scope, inherited_env):
        env, barrier = dict(inherited_env), False
        for node in scope.children:
            self.r.step(node)
            if node.name == 'set' and not node.block and len(node.args) == 2:
                name = destination_name(node.args[0])
                self.r.data['counts']['set_providers'] += 1
                if name is None or name in REQUEST_NAMES or name.startswith(REQUEST_PREFIXES) or name == 'scheme':
                    self.r.add('OPEN', 'set_destination', 'Set destination is invalid or a protected builtin within this profile.', node, incomplete=True)
                    if name:
                        env[name] = Value('unknown', providers=(node,))
                    continue
                env[name] = Value('unknown', providers=(node,)) if barrier else self.expression(node.args[1], env, (), node)
                if len(env) > self.r.limits.variables:
                    self.r.stop('variable_limit', 'Scoped variable budget exhausted.', node)
            elif node.name == 'if' and node.block:
                branch = self.assignments(node, env)
                for name in set(env) | set(branch):
                    env[name] = merge(env.get(name, Value('unknown')), branch.get(name, Value('unknown')), self.r, node)
            elif node.name in ('return', 'break') and not node.block:
                break
            elif node.name == 'rewrite' and not node.block:
                barrier = True
                env = {name: Value('unknown', providers=(node,)) for name in env}
        return env

    def access_rule(self, scope):
        rules = self.access(scope)
        selective, first_terminal, valid = [], None, True
        for rule in rules:
            self.r.step(rule)
            if len(rule.args) != 1:
                valid = False; continue
            text = rule.args[0]
            if text == 'all':
                if first_terminal is None:
                    first_terminal = rule.name
            elif text == 'unix:':
                if rule.name == 'allow':
                    selective.append(rule)
            else:
                try:
                    ipaddress.ip_network(text, strict=False)
                except ValueError:
                    self.r.add('OPEN', 'access_address_unknown', 'Access address is outside numeric address/CIDR/all/unix profile.', rule, rule='allow_without_deny')
                    valid = False; continue
                if rule.name == 'allow':
                    selective.append(rule)
        if selective and valid and first_terminal != 'deny':
            satisfy = self.inherited(scope, 'satisfy')
            auth = [self.inherited(scope, name) for name in AUTH]
            if satisfy and satisfy.args == ('any',) and any(n and n.args and n.args[0] != 'off' for n in auth):
                self.r.add('OPEN', 'allow_auth_alternative', 'satisfy any plus authentication makes allowlist intent/provider result unknown.', selective[0], rule='allow_without_deny')
            else:
                self.r.add('FAIL', 'allow_without_catchall_deny', 'Selective allow rules do not reach a first terminal deny all; unmatched clients are not denied by this list.', selective[0], rule='allow_without_deny', related=tuple(rules))
        return rules

    def alias_rule(self, scope):
        alias = self.inherited(scope, 'alias')
        if alias is None or len(alias.args) != 1:
            return
        kind, prefix = location_kind(scope)
        if alias.parent is not scope or kind not in ('prefix', 'high_prefix', 'exact') or '$' in prefix or '$' in alias.args[0] or not prefix.startswith('/') or not alias.args[0].startswith('/') or '\\' in alias.args[0]:
            self.r.add('OPEN', 'alias_mapping_unknown', 'Inherited/regex/named/dynamic/non-absolute alias mapping is outside static prefix/exact profile.', alias, rule='alias_mapping', related=(scope,))
        elif kind != 'exact':
            target = alias.args[0]
            if not prefix.endswith('/') and target.endswith('/'):
                self.r.add('FAIL', 'alias_prefix_boundary', 'Directory alias replaces a prefix lacking a component separator; suffix concatenation can leave the intended directory boundary.', alias, rule='alias_mapping', related=(scope,))
            elif prefix.endswith('/') and not target.endswith('/'):
                self.r.add('FAIL', 'alias_target_separator', 'Directory-prefix suffix concatenation has no target separator and can form sibling names.', alias, rule='alias_mapping', related=(scope,))
            elif not prefix.endswith('/'):
                self.r.add('OPEN', 'alias_both_separators_missing', 'Both prefix and alias lack terminal separators; file/directory intent and mapping boundary are ambiguous.', alias, rule='alias_mapping', related=(scope,))

    def return_rule(self, node, scope, conditional=False):
        rules = self.access(scope)
        auth_controls = [self.inherited(scope, name) for name in AUTH]
        auth_controls = [n for n in auth_controls if n and len(n.args) == 1 and n.args[0] != 'off']
        method_controls = []
        for child in scope.children:
            if child.name == 'limit_except' and child.block:
                method_controls += self.access(child)
        if scope.name == 'server':
            # Server rewrite runs before location selection/access; location ACLs
            # cannot guard an earlier server-level response.
            for child in scope.children:
                if child.name == 'location' and child.block:
                    rules += self.access(child)
                    auth_controls += [n for n in (self.inherited(child, name) for name in AUTH) if n and len(n.args) == 1 and n.args[0] != 'off']
        restricted = [n for n in rules + method_controls if n.name == 'deny' or n.args != ('all',)] + auth_controls
        if not restricted:
            return
        code = None
        if node.args and node.args[0].isascii() and node.args[0].isdigit():
            code = int(node.args[0])
        elif node.args and node.args[0].startswith(('http://', 'https://', '$scheme')):
            code = 302
        if code is None or not 0 <= code <= 599:
            self.r.add('OPEN', 'return_response_unknown', 'Return response syntax is outside supported profile.', node, rule='return_access_phase', related=tuple(restricted))
            return
        internal = self.inherited(scope, 'internal') is not None or (scope.name == 'location' and location_kind(scope)[0] == 'named')
        uncertain = conditional or internal or code >= 400 or bool(method_controls)
        self.r.add('OPEN' if uncertain else 'FAIL', 'return_before_access', 'Return produces/stops a response in rewrite phase before referenced address/authentication access controls; response intent/reachability is not an observed bypass.', node, rule='return_access_phase', related=tuple(restricted))

    def proxy_rule(self, node, env):
        if len(node.args) != 1:
            return
        self.r.data['counts']['proxy_targets'] += 1
        parts = variables(node.args[0])
        if parts is None:
            self.r.add('OPEN', 'proxy_template_unknown', 'Proxy script syntax is unresolved.', node, rule='untrusted_proxy_destination'); return
        candidates = [()]
        for kind, text in parts:
            self.r.step(node)
            val = Value('finite', (text,)) if kind == 'literal' else self.resolve(text, env, (), node)
            candidates = self.extend_forms(candidates, val, node)
        for candidate in candidates:
            self.r.step(node)
            first = candidate[0] if candidate else Value('finite', ('',))
            if first.kind != 'finite':
                self.r.add('FAIL' if first.kind == 'untrusted' else 'OPEN', 'proxy_dynamic_scheme', 'Untrusted or unresolved variable determines protocol/target prefix.', node, rule='untrusted_proxy_destination', related=first.providers); continue
            text = first.options[0]
            if not text.startswith(('http://', 'https://')):
                self.r.add('OPEN', 'proxy_scheme_unknown', 'Proxy destination protocol is outside literal HTTP/HTTPS profile.', node, rule='untrusted_proxy_destination'); continue
            authority = text.split('://', 1)[1]
            terminated = '/' in authority
            authority = authority.split('/', 1)[0]
            if '#' in authority or '?' in authority:
                self.r.add('OPEN', 'proxy_authority_unknown', 'Query/fragment-like bytes before a literal slash are outside the strict authority profile.', node, rule='untrusted_proxy_destination')
                continue
            if terminated or len(candidate) == 1:
                try:
                    parsed = urlsplit('http://' + authority)
                    valid = bool(parsed.hostname) and parsed.username is None and parsed.password is None and not any(c.isspace() for c in authority) and '\\' not in authority
                    parsed.port
                except ValueError:
                    valid = False
                if not valid or authority.startswith('unix:'):
                    self.r.add('OPEN', 'proxy_authority_unknown', 'Literal authority is malformed or outside domain/IP/upstream profile.', node, rule='untrusted_proxy_destination')
                continue  # Variables after a literal URI separator cannot choose authority.
            for part in candidate[1:]:
                if part.kind == 'finite':
                    if '/' in part.options[0]:
                        break
                else:
                    self.r.add('FAIL' if part.kind == 'untrusted' else 'OPEN', 'proxy_variable_authority', 'Untrusted or unresolved variable reaches proxy destination authority before a literal URI boundary.', node, rule='untrusted_proxy_destination', related=part.providers)

    def analyze_scope(self, scope, parent_env):
        self.r.step(scope)
        # Location rewrite directives belong to the selected location. Parent
        # location execution/inheritance is deliberately left OPEN for nesting.
        env = self.assignments(scope, parent_env)
        self.access_rule(scope)
        if scope.name == 'location':
            self.alias_rule(scope)
        for node in scope.children:
            if not node.block and node.name == 'return':
                self.return_rule(node, scope)
            elif not node.block and node.name == 'proxy_pass':
                self.proxy_rule(node, env)
            elif node.block and node.name == 'if':
                for item in node.children:
                    if item.name == 'return' and not item.block:
                        self.return_rule(item, scope, conditional=True)
                    elif item.name == 'proxy_pass' and not item.block:
                        self.proxy_rule(item, env)
            elif node.block and node.name in ('server', 'location', 'limit_except'):
                self.analyze_scope(node, env)

    def run(self):
        self.structure(self.root)
        http = [n for n in self.root.children if n.name == 'http' and n.block]
        if len(http) != 1:
            self.r.add('OPEN', 'http_profile', 'Exactly one main HTTP block is required; standalone fragments/stream profiles are unsupported.', self.root, incomplete=True)
        for scope in http:
            self.analyze_scope(scope, {})
