"""Independent byte lexer and nested AST; no regex parser or external runtime."""
from dataclasses import dataclass, field

WHITE = frozenset(b' \t\r\n')


@dataclass
class Token:
    value: str
    offset: int
    line: int
    column: int
    kind: str = 'word'

    def position(self):
        return {'byte_offset': self.offset, 'line': self.line, 'byte_column': self.column}


@dataclass
class Node:
    name: str
    args: tuple[str, ...]
    token: Token
    children: list = field(default_factory=list)
    parent: object = None
    block: bool = False
    identifier: int = 0

    def position(self):
        return self.token.position()

    def direct(self, name):
        return [n for n in self.children if n.name == name and not n.block]


class Lexer:
    def __init__(self, data, report):
        self.data, self.r = data, report
        self.i, self.line, self.column = 0, 1, 1

    def advance(self):
        ch = self.data[self.i]
        self.i += 1
        if ch == 10:
            self.line += 1; self.column = 1
        else:
            self.column += 1
        return ch

    def emit(self, value, start, kind='word'):
        if self.i - start.offset > self.r.limits.token_bytes:
            self.r.stop('token_bytes', 'Token byte budget exhausted.', start)
        self.r.data['counts']['tokens'] += 1
        if self.r.data['counts']['tokens'] > self.r.limits.tokens:
            self.r.stop('token_limit', 'Lexer token budget exhausted.', start)
        try:
            text = bytes(value).decode('utf-8')
        except UnicodeError:
            self.r.stop('encoding', 'Token is outside strict UTF-8 profile.', start)
        return Token(text, start.offset, start.line, start.column, kind)

    def tokens(self):
        while self.i < len(self.data):
            ch = self.data[self.i]
            if ch in WHITE:
                self.advance(); continue
            if ch == 35:
                while self.i < len(self.data) and self.data[self.i] != 10:
                    self.advance()
                continue
            start = Token('', self.i, self.line, self.column)
            if ch in b';{}':
                self.advance()
                yield self.emit(bytes([ch]), start, chr(ch)); continue
            value, quote, closed = bytearray(), None, False
            if ch in (34, 39):
                quote = self.advance()
            while self.i < len(self.data):
                if self.i - start.offset >= self.r.limits.token_bytes:
                    self.r.stop('token_bytes', 'Token byte budget exhausted.', start)
                ch = self.data[self.i]
                if ch == 0:
                    self.r.stop('nul_byte', 'NUL byte is outside supported configuration profile.', start)
                if ch == 92:
                    self.advance()
                    if self.i == len(self.data):
                        self.r.stop('truncated_escape', 'Trailing escape has no following byte.', start)
                    escaped = self.advance()
                    decoded = {34: 34, 39: 39, 92: 92, 116: 9, 114: 13, 110: 10}
                    if escaped in decoded:
                        value.append(decoded[escaped])
                    else:
                        # Nginx retains other backslashes in the argument value.
                        value.extend((92, escaped))
                    continue
                if quote:
                    if ch == quote:
                        self.advance(); closed = True; break
                    value.append(self.advance()); continue
                if ch in WHITE or ch == 59 or (ch == 123 and (not value or value[-1] != 36)):
                    break
                # Quotes and # within an unquoted word remain literal bytes;
                # ${name} braces are preserved rather than opening a scope.
                value.append(self.advance())
            if quote and not closed:
                self.r.stop('unterminated_quote', 'Quoted argument has no closing quote.', start)
            if closed and self.i < len(self.data) and self.data[self.i] not in WHITE | frozenset(b';{)'):
                self.r.stop('quote_suffix', 'Quoted token has unsupported adjacent suffix.', start)
            yield self.emit(value, start)


class Parser:
    def __init__(self, data, report):
        self.r = report
        self.tokens = iter(Lexer(data, report).tokens())
        self.root = Node('main', (), Token('', 0, 1, 1), block=True)

    def parse(self):
        stack, header = [self.root], []
        for token in self.tokens:
            if token.kind == 'word':
                header.append(token)
                if len(header) > self.r.limits.arguments + 1:
                    self.r.stop('argument_limit', 'Directive argument budget exhausted.', token)
                continue
            if token.kind == '}':
                if header or len(stack) == 1:
                    self.r.stop('unbalanced_close', 'Closing brace does not match a completed block.', token)
                stack.pop(); continue
            if not header:
                self.r.stop('empty_directive', 'Delimiter has no directive header.', token)
            self.r.data['counts']['nodes'] += 1
            if self.r.data['counts']['nodes'] > self.r.limits.nodes:
                self.r.stop('node_limit', 'AST node budget exhausted.', header[0])
            node = Node(header[0].value, tuple(t.value for t in header[1:]), header[0],
                        parent=stack[-1], block=token.kind == '{', identifier=self.r.data['counts']['nodes'])
            stack[-1].children.append(node); header = []
            if node.block:
                if 'lua' in node.name.lower() or 'perl' in node.name.lower():
                    self.r.stop('embedded_language', 'Embedded language is unsupported and never executed.', node)
                stack.append(node)
                if len(stack) - 1 > self.r.limits.nesting:
                    self.r.stop('nesting_limit', 'Block nesting budget exhausted.', node)
        if header or len(stack) != 1:
            self.r.stop('truncated_syntax', 'Input ends with an unfinished directive or block.', header[0] if header else stack[-1])
        if not self.root.children:
            self.r.stop('empty_configuration', 'No configuration directives were observed.')
        self.r.data['parse_complete'] = True
        return self.root


def location_kind(node):
    args = node.args
    if len(args) == 1:
        return ('named' if args[0].startswith('@') else ('dynamic' if '$' in args[0] else 'prefix')), args[0]
    if len(args) == 2 and args[0] in ('=', '^~', '~', '~*'):
        return {'=': 'exact', '^~': 'high_prefix', '~': 'regex', '~*': 'regex'}[args[0]], args[1]
    return 'unknown', ''


def select_location(server, normalized_uri):
    """Flat, case-sensitive normalized-URI selection; no PCRE or request generation.

    Returns (node-or-None, complete, reason). Nested/regex/dynamic candidates retain
    uncertainty except an exact match or a selected ^~ prefix excluding regexes.
    """
    locations = [n for n in server.children if n.block and n.name == 'location']
    exact = [n for n in locations if location_kind(n) == ('exact', normalized_uri)]
    if len(exact) == 1:
        return exact[0], True, 'exact'
    if len(exact) > 1:
        return None, False, 'duplicate'
    prefixes = [n for n in locations if location_kind(n)[0] in ('prefix', 'high_prefix') and normalized_uri.startswith(location_kind(n)[1])]
    prefixes.sort(key=lambda n: len(location_kind(n)[1]), reverse=True)
    best = prefixes[0] if prefixes else None
    if len(prefixes) > 1 and len(location_kind(prefixes[0])[1]) == len(location_kind(prefixes[1])[1]):
        return None, False, 'duplicate'
    if best and any(n.name == 'location' and n.block for n in best.children):
        return best, False, 'nested'
    if best and location_kind(best)[0] == 'high_prefix':
        return best, True, 'high_prefix'
    if any(location_kind(n)[0] in ('regex', 'dynamic', 'unknown') for n in locations):
        return best, False, 'regex_or_dynamic'
    return best, True, 'longest_prefix' if best else 'server_fallback'
