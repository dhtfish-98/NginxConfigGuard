"""Bounded read-only input and private, position-only reporting."""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import stat

RULES = ('alias_mapping', 'allow_without_deny', 'return_access_phase', 'untrusted_proxy_destination')


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 1024 * 1024
    tokens: int = 50000
    token_bytes: int = 4096
    arguments: int = 128
    nodes: int = 10000
    scopes: int = 256
    nesting: int = 32
    variables: int = 512
    alternatives: int = 16
    map_entries: int = 256
    model_steps: int = 50000
    findings: int = 200
    report_bytes: int = 128 * 1024

    def validate(self):
        defaults = Limits()
        for key, value in asdict(self).items():
            if type(value) is not int or not 1 <= value <= getattr(defaults, key):
                raise ValueError('Limits must be positive integers no greater than defaults')
        if self.findings < 2 or self.report_bytes < 8192:
            raise ValueError('At least 2 findings and 8192 report bytes required')


class Stop(Exception):
    pass


class Report:
    def __init__(self, limits):
        self.limits = limits
        self.steps = 0
        self.first_failure = None
        self.data = {'schema': 'nginx-config-guard/1', 'status': 'OPEN',
                     'result_scope': 'four selected static HTTP configuration policies',
                     'deployment_security': 'OPEN', 'nginx_configuration_validity': 'OPEN',
                     'application_eligibility': 'OPEN', 'parse_complete': False,
                     'coverage_complete': True, 'input_sha256': None, 'input_bytes': None,
                     'limits': asdict(limits), 'counts': {'tokens': 0, 'nodes': 0, 'scopes': 0,
                     'map_providers': 0, 'set_providers': 0, 'proxy_targets': 0},
                     'selected_rules': {rule: 'PASS' for rule in RULES},
                     'other_gixy_plugins': 'UNIMPLEMENTED', 'scopes': [], 'findings': [],
                     'privacy': 'Paths, directive arguments, identifiers, credentials, addresses, source excerpts and raw exception text are suppressed.'}

    def add(self, status, code, detail, node=None, *, rule=None, related=(), incomplete=False):
        if incomplete:
            self.data['coverage_complete'] = False
        if rule:
            previous = self.data['selected_rules'][rule]
            self.data['selected_rules'][rule] = 'FAIL' if 'FAIL' in (previous, status) else 'OPEN'
        finding = {'status': status, 'code': code, 'rule': rule,
                   'position': node.position() if node is not None else None,
                   'related_positions': [n.position() for n in related[:8]], 'detail': detail}
        if status == 'FAIL' and self.first_failure is None:
            self.first_failure = finding
        if len(self.data['findings']) >= self.limits.findings - 1:
            retained = self.data['findings'][:self.limits.findings - 1]
            # A newly demonstrated failure must survive the last reserved slot.
            # Keep its supporting position rather than only the selected-rule flag.
            if self.first_failure is not None and self.first_failure not in retained:
                retained[-1] = self.first_failure
            self.data['findings'] = retained + [{'status': 'OPEN', 'code': 'finding_limit', 'rule': None,
                                         'position': finding['position'], 'related_positions': [],
                                         'detail': 'Finding budget exhausted; review is partial.'}]
            self.data['coverage_complete'] = False
            raise Stop
        self.data['findings'].append(finding)

    def stop(self, code, detail, node=None):
        self.add('OPEN', code, detail, node, incomplete=True)
        raise Stop

    def step(self, node=None):
        self.steps += 1
        if self.steps > self.limits.model_steps:
            self.stop('model_limit', 'Semantic model work budget exhausted.', node)

    def finish(self):
        if not self.data['coverage_complete'] or not self.data['parse_complete']:
            for rule, value in self.data['selected_rules'].items():
                if value == 'PASS':
                    self.data['selected_rules'][rule] = 'OPEN'
        flags = {f['status'] for f in self.data['findings']}
        self.data['status'] = 'FAIL' if self.first_failure is not None or 'FAIL' in flags else ('OPEN' if 'OPEN' in flags or not self.data['parse_complete'] or not self.data['coverage_complete'] else 'PASS')
        if len(json.dumps(self.data, ensure_ascii=True).encode()) > self.limits.report_bytes:
            fail = next((f for f in self.data['findings'] if f['status'] == 'FAIL'), None)
            self.data['scopes'] = []
            self.data['findings'] = [{'status': 'OPEN', 'code': 'report_limit', 'rule': None,
                                     'position': None, 'related_positions': [],
                                     'detail': 'Report budget exhausted; detailed inventory removed.'}]
            if fail:
                self.data['findings'].append(fail)
            self.data['coverage_complete'] = False
            for rule, value in self.data['selected_rules'].items():
                if value == 'PASS':
                    self.data['selected_rules'][rule] = 'OPEN'
            if self.data['status'] != 'FAIL':
                self.data['status'] = 'OPEN'
        return self.data


def read_local(path, report):
    value = os.fspath(path)
    if not isinstance(value, str) or not value or value == '-' or value.startswith('@') or '://' in value:
        report.stop('input_contract', 'One explicit local regular file is required; URL/stdin/@list unsupported.')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(value, flags), 'rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            report.stop('input_type', 'Input is not a regular file.')
        if before.st_size > report.limits.input_bytes:
            report.stop('input_limit', 'Input exceeds raw byte budget.')
        data = handle.read(report.limits.input_bytes + 1)
        after = os.fstat(handle.fileno())
        if len(data) > report.limits.input_bytes:
            report.stop('input_limit', 'Input grew beyond raw byte budget.')
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != after.st_size:
            report.stop('input_changed', 'Input changed during observation.')
    report.data['input_sha256'] = hashlib.sha256(data).hexdigest()
    report.data['input_bytes'] = len(data)
    return data
