"""Inert local configurations; semantic positives, counterexamples and budgets."""
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.request

from nginx_config_guard import Limits, review_config
from nginx_config_guard.cli import main
from nginx_config_guard.parser import Parser, location_kind, select_location
from nginx_config_guard.report import Report


def config(body='proxy_pass http://fixed.invalid/;', *, prefix='/', server='', http='', extra='', modifier=''):
    return ('events {} ' + extra + ' http { ' + http + ' server { ' + server + ' location ' + modifier + ' ' + prefix + ' { ' + body + ' } } }').encode()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name);self.path = self.root/'private-config.conf'

    def check(self, data=None, **kw):
        data = config() if data is None else data
        self.path.write_bytes(data)
        before = self.path.read_bytes()
        report = review_config(self.path, **kw)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(report['deployment_security'], 'OPEN')
        self.assertEqual(report['nginx_configuration_validity'], 'OPEN')
        self.assertEqual(report['application_eligibility'], 'OPEN')
        self.assertNotIn(str(self.path), json.dumps(report))
        self.assertLessEqual(len(json.dumps(report).encode()), kw.get('limits', Limits()).report_bytes)
        return report

    def expect(self, code, data, status='OPEN', **kw):
        r = self.check(data, **kw)
        self.assertEqual(r['status'], status, r)
        self.assertIn(code, {f['code'] for f in r['findings']}, r)
        return r

    def test_supported_literal_baseline(self):
        r = self.check();self.assertEqual(r['status'], 'PASS', r)
        self.assertTrue(r['parse_complete']);self.assertTrue(r['coverage_complete'])
        self.assertEqual(r['input_sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(r['counts']['scopes'], 3)

    def test_alias_slash_cross_product(self):
        self.assertEqual(self.check(config('alias /srv/static/;', prefix='/assets/'))['status'], 'PASS')
        self.expect('alias_prefix_boundary', config('alias /srv/static/;', prefix='/assets'), 'FAIL')
        self.expect('alias_target_separator', config('alias /srv/static;', prefix='/assets/'), 'FAIL')
        self.expect('alias_both_separators_missing', config('alias /srv/static;', prefix='/assets'))

    def test_alias_exact_file_is_not_prefix_concatenation(self):
        self.assertEqual(self.check(config('alias /srv/file;', prefix='/asset', modifier='='))['status'], 'PASS')

    def test_alias_regex_dynamic_and_named_open(self):
        for data in [config('alias /srv/$1;',prefix='^/item/(.*)$',modifier='~'),config('alias $destination;'),config('alias /srv/x/;',prefix='@fallback'),config('alias /srv/x/;',prefix='$request_uri')]:
            self.expect('alias_mapping_unknown',data)

    def test_alias_inherited_nested_is_not_assumed_safe(self):
        self.expect('alias_mapping_unknown',config('alias /srv/static/; location /assets/deep/ {}',prefix='/assets/'))

    def test_quotes_comments_and_escaped_delimiters(self):
        body = r'alias "/srv/;{#private}/"; # alias /private/; return 200;'+ '\n'
        r=self.check(config(body,prefix='/assets/'));self.assertEqual(r['status'],'PASS',r)
        raw=b'http { server { location / { set $v "quoted\\\";{#x}"; proxy_pass http://fixed.invalid/; } } }'
        self.assertEqual(self.check(raw)['status'],'PASS')
        ast=Parser(b'http { server { location / { set $v x\\;y; } } }',Report(Limits())).parse()
        self.assertEqual(ast.children[0].children[0].children[0].children[0].args[1],r'x\;y')

    def test_quotes_in_unquoted_words_and_hash_are_literal(self):
        ast=Parser(b'http { server { location / { set $v abc#def; set $q abc"def; } } }',Report(Limits())).parse()
        self.assertEqual(ast.children[0].children[0].children[0].children[0].args[1],'abc#def')
        self.assertEqual(ast.children[0].children[0].children[0].children[1].args[1],'abc"def')

    def test_escape_decode_matches_nginx_quote_backslash_t_r_n_only(self):
        ast=Parser(b'http { server { location / { set $v "a\\tb\\rc\\nd\\\\e\\\"f\\\'g\\{h"; } } }',Report(Limits())).parse()
        self.assertEqual(ast.children[0].children[0].children[0].children[0].args[1],'a\tb\rc\nd\\e"f\'g\\{h')

    def test_braced_variable_is_not_a_scope(self):
        self.expect('proxy_variable_authority',config('proxy_pass http://${arg_destination}/;'),'FAIL')

    def test_allow_needs_catchall_not_any_deny(self):
        self.expect('allow_without_catchall_deny',config('allow 192.0.2.0/24;'),'FAIL')
        self.expect('allow_without_catchall_deny',config('allow 192.0.2.0/24; deny 198.51.100.0/24;'),'FAIL')
        self.assertEqual(self.check(config('allow 192.0.2.0/24; deny all;'))['status'],'PASS')

    def test_access_order_terminal_allow_is_not_restriction(self):
        self.expect('allow_without_catchall_deny',config('allow 192.0.2.0/24; allow all; deny all;'),'FAIL')
        self.assertEqual(self.check(config('deny all; allow 192.0.2.0/24;'))['status'],'PASS')
        self.assertEqual(self.check(config('allow all;'))['status'],'PASS')

    def test_access_complete_list_inheritance_and_override(self):
        self.assertEqual(self.check(config('',server='allow 192.0.2.0/24; deny all;'))['status'],'PASS')
        self.expect('allow_without_catchall_deny',config('allow 198.51.100.1;',server='allow 192.0.2.0/24; deny all;'),'FAIL')
        self.assertEqual(self.check(config('allow 198.51.100.1; deny all;',server='allow 192.0.2.0/24; deny all;'))['status'],'PASS')

    def test_access_http_inherits_into_server_and_location(self):
        r=self.expect('allow_without_catchall_deny',config('',http='allow 192.0.2.1;'),'FAIL')
        self.assertGreaterEqual(len([f for f in r['findings'] if f['code']=='allow_without_catchall_deny']),3)

    def test_access_ipv6_unix_and_invalid_address(self):
        self.assertEqual(self.check(config('allow 2001:db8::/32; allow unix:; deny all;'))['status'],'PASS')
        self.expect('access_address_unknown',config('allow private-host.invalid; deny all;'))

    def test_auth_alternative_is_open_and_off_override_is_real(self):
        self.expect('allow_auth_alternative',config('allow 192.0.2.1;',server='satisfy any; auth_basic private-realm;'))
        self.expect('allow_without_catchall_deny',config('allow 192.0.2.1; auth_basic off;',server='satisfy any; auth_basic private-realm;'),'FAIL')
        self.expect('satisfy_value',config('satisfy invalid;'))

    def test_return_conflicts_with_inherited_access(self):
        r=self.expect('return_before_access',config('return 200 private-body;',server='deny all;'),'FAIL')
        f=next(f for f in r['findings'] if f['code']=='return_before_access')
        self.assertTrue(f['related_positions']);self.assertNotIn('private-body',json.dumps(r))

    def test_return_server_precedes_location_access(self):
        self.expect('return_before_access',config('deny all;',server='return 302 https://private.invalid/;'),'FAIL')

    def test_return_authentication_phase_and_disabled_auth(self):
        self.expect('return_before_access',config('return 200;',server='auth_basic private-realm;'),'FAIL')
        self.assertEqual(self.check(config('auth_basic off; return 200;',server='auth_basic private-realm;'))['status'],'PASS')

    def test_return_without_restriction_is_not_conflict(self):
        self.assertEqual(self.check(config('return 200;'))['status'],'PASS')
        self.assertEqual(self.check(config('allow all; return 301 /;'))['status'],'PASS')

    def test_conditional_denial_internal_named_and_method_returns_open(self):
        for data in [config('deny all; if ($arg_decision) { return 200; }'),config('deny all; return 403;'),config('internal; deny all; return 200;'),config('deny all; return 200;',prefix='@fallback'),config('limit_except GET { deny all; } return 200;')]:
            self.expect('return_before_access',data)

    def test_return_and_directive_bad_context_shape_are_open(self):
        for data in [config('return invalid;'),config('alias;'),config('proxy_pass;'),config('allow;'),config('satisfy;'),b'http { alias /private/; server { location / {} } }']:
            self.assertEqual(self.check(data)['status'],'OPEN')

    def test_direct_proxy_request_family_sources(self):
        for source in ['$host','$arg_destination','$http_private','$cookie_private','$remote_addr','$1']:
            self.expect('proxy_variable_authority',config('proxy_pass http://'+source+'/;'),'FAIL')
        self.expect('proxy_dynamic_scheme',config('proxy_pass $arg_destination;'),'FAIL')

    def test_only_literal_uri_boundary_excludes_path_taint(self):
        for value in ['http://fixed.invalid/$request_uri','https://[::1]:8443/$arg_private','http://upstream_name/path?x=$http_private']:
            self.assertEqual(self.check(config('proxy_pass '+value+';'))['status'],'PASS')
        self.expect('proxy_variable_authority',config('proxy_pass http://fixed.invalid$request_uri;'),'FAIL')

    def test_symbolic_uri_boundaries_survive_set_and_map_provenance(self):
        self.assertEqual(self.check(config('set $target http://fixed.invalid/$request_uri; proxy_pass $target;'))['status'],'PASS')
        self.assertEqual(self.check(config('proxy_pass $target;',http='map $arg_key $target { default http://fixed.invalid/$request_uri; key https://other.invalid/path?x=$arg_private; }'))['status'],'PASS')
        self.expect('proxy_variable_authority',config('set $target http://$arg_destination/path; proxy_pass $target;'),'FAIL')
        self.expect('proxy_authority_unknown',config('proxy_pass http://fixed.invalid#$arg_private;'))
        self.expect('proxy_authority_unknown',config('proxy_pass http://fixed.invalid?$http_private;'))
        self.expect('proxy_authority_unknown',config('proxy_pass http://[::1]?$http_private;'))

    def test_set_transitive_order_and_server_scope(self):
        self.expect('proxy_variable_authority',config('set $first $arg_destination; set $second ${first}; proxy_pass http://$second/;'),'FAIL')
        self.expect('proxy_variable_authority',config('proxy_pass http://$second/;',server='set $first $http_private; set $second $first;'),'FAIL')
        self.assertEqual(self.check(config('set $x $arg_destination; set $x fixed.invalid; proxy_pass http://$x/;'))['status'],'PASS')
        self.expect('proxy_variable_authority',config('set $x fixed.invalid; set $x $arg_destination; proxy_pass http://$x/;'),'FAIL')

    def test_location_siblings_do_not_share_set_values(self):
        self.expect('proxy_variable_authority',config('set $dest fixed.invalid; proxy_pass http://$dest/; location /child/ {}',server='location /other/ { set $dest $arg_destination; proxy_pass http://$dest/; }'),'FAIL')

    def test_set_after_proxy_runs_before_content_phase(self):
        self.assertEqual(self.check(config('proxy_pass http://$target/; set $target fixed.invalid;'))['status'],'PASS')

    def test_forward_unknown_cycle_and_builtin_assignments_open(self):
        self.expect('proxy_variable_authority',config('set $a $b; set $b fixed.invalid; proxy_pass http://$a/;'))
        self.expect('proxy_variable_authority',config('set $a $a; proxy_pass http://$a/;'))
        self.expect('set_destination',config('set $host fixed.invalid; proxy_pass http://$host/;'))
        self.assertEqual(self.check(config('proxy_pass $scheme://fixed.invalid/;'))['status'],'PASS')

    def test_conditional_assignments_join_then_later_override(self):
        self.expect('proxy_variable_authority',config('set $target fixed.invalid; if ($arg_x) { set $target $arg_destination; } proxy_pass http://$target/;'),'FAIL')
        r=self.expect('conditional_scope',config('set $target fixed.invalid; if ($arg_x) { set $target $arg_destination; } set $target fixed.invalid; proxy_pass http://$target/;'))
        self.assertNotIn('proxy_variable_authority',{f['code'] for f in r['findings']})

    def test_lazy_map_literals_bound_untrusted_lookup(self):
        http='map $arg_source $target { default fixed.invalid; first other.invalid; }'
        self.assertEqual(self.check(config('proxy_pass http://$target/;',http=http))['status'],'PASS')
        r=self.check(config('proxy_pass http://$target/;',http='map $http_private $target { default fixed.invalid; proxy_pass other.invalid; }'))
        self.assertEqual(r['status'],'PASS')
        self.assertEqual(r['counts']['proxy_targets'],1) # map key is data

    def test_lazy_map_output_variables_propagate_request_taint(self):
        self.expect('proxy_variable_authority',config('proxy_pass http://$target/;',http='map $arg_source $target { default fixed.invalid; key $arg_destination; }'),'FAIL')
        self.assertEqual(self.check(config('set $defined fixed.invalid; proxy_pass http://$target/;',http='map $arg_source $target { default $defined; }'))['status'],'PASS')

    def test_lazy_map_first_use_cache_survives_later_input_set(self):
        http='map $arg_choice $target { default $source; }'
        self.expect('proxy_variable_authority',config('set $source $arg_destination; set $discard $target; set $source fixed.invalid; proxy_pass http://$target/;',http=http),'FAIL')
        self.assertEqual(self.check(config('set $source fixed.invalid; set $discard $target; set $source $arg_destination; proxy_pass http://$target/;',http=http))['status'],'PASS')

    def test_unused_unsupported_maps_still_open_coverage(self):
        self.expect('map_default_profile',config('',http='map $arg_x $target { key fixed.invalid; }'))
        self.expect('map_duplicate_key',config('',http='map $arg_x $target { default fixed.invalid; key one.invalid; KEY two.invalid; }'))

    def test_map_lookup_source_evaluates_nested_map_first_use(self):
        http='map $arg_x $inner { default $source; } map $inner $outer { default fixed.invalid; }'
        self.expect('proxy_variable_authority',config('set $source $arg_destination; set $discard $outer; set $source fixed.invalid; proxy_pass http://$inner/;',http=http),'FAIL')

    def test_map_branch_only_nested_evaluation_does_not_cache_safe_value_for_all_paths(self):
        http='map $arg_x $inner { default $source; } map $arg_y $outer { default fixed.invalid; key $inner; }'
        self.expect('proxy_variable_authority',config('set $source fixed.invalid; set $discard $outer; set $source $arg_destination; proxy_pass http://$inner/;',http=http))

    def test_lazy_map_missing_default_cycle_duplicate_and_regex_open(self):
        for http in ['map $arg_x $target { key fixed.invalid; }','map $arg_x $target { default $target; }','map $arg_x $target { default fixed.invalid; default other.invalid; }','map $arg_x $target { default fixed.invalid; ~private-regex other.invalid; }','map $arg_x $target { default fixed.invalid; hostnames; }']:
            self.assertEqual(self.check(config('proxy_pass http://$target/;',http=http))['status'],'OPEN')
        self.expect('duplicate_variable_provider',config('proxy_pass http://$target/;',http='map $arg_x $target { default fixed.invalid; } map $arg_x $target { default other.invalid; }'))

    def test_proxy_literal_bad_or_unknown_authority_open(self):
        for value in ['http:///','http://private-user:private-pass@host.invalid/','ftp://fixed.invalid/','http://unix:/private/socket:/','http://$unknown/']:
            self.assertEqual(self.check(config('proxy_pass '+value+';'))['status'],'OPEN')

    def test_flat_location_priority_is_exact_longest_and_high_prefix(self):
        root=Parser(b'http { server { location / {} location /deep/ {} location = /deep/exact {} location ^~ /fixed/ {} location ~ "private-regex" {} } }',Report(Limits())).parse()
        server=root.children[0].children[0]
        node,complete,reason=select_location(server,'/deep/exact');self.assertEqual(location_kind(node)[0],'exact');self.assertTrue(complete)
        node,complete,reason=select_location(server,'/fixed/file');self.assertTrue(complete);self.assertEqual(reason,'high_prefix')
        node,complete,reason=select_location(server,'/deep/file');self.assertFalse(complete);self.assertEqual(location_kind(node)[1],'/deep/')
        plain=Parser(b'http { server { location / {} location /deep/ {} } }',Report(Limits())).parse().children[0].children[0]
        self.assertEqual(location_kind(select_location(plain,'/deep/file')[0])[1],'/deep/')

    def test_duplicate_and_nested_routing_is_open(self):
        self.expect('duplicate_location',config('',server='location / {}'))
        self.expect('nested_location_selection',config('location /child/ {}'))
        self.expect('location_selection_unknown',config('',prefix='private-regex',modifier='~'))

    def test_include_never_reads_self_mutual_glob_or_symlink(self):
        secret=self.root/'included-private.conf';secret.write_bytes(b'private-secret')
        link=self.root/'private-link';link.symlink_to(secret)
        for value in [str(self.path),str(secret),str(link),'../outside-private','*.conf','$variable']:
            original=os.open
            with mock.patch.object(os,'open',wraps=original) as opened:
                self.expect('include_unexpanded',config('',http='include "'+value+'";'))
                self.assertEqual(opened.call_count,1)
            self.assertEqual(secret.read_bytes(),b'private-secret')

    def test_embedded_program_and_unknown_plugin_paths_open(self):
        for body in ['content_by_lua_block { private_program() }','perl private_secret;','unknown_module private_secret;']:
            self.assertEqual(self.check(config(body))['status'],'OPEN')
        self.expect('rewrite_control_flow',config('rewrite private_regex /new last; set $target fixed.invalid; proxy_pass http://$target/;'))

    def test_syntax_truncation_quote_suffix_nul_and_unknown_bytes(self):
        for data in [b'',b'# comment only',b'http {',b'http { server { alias "private',b'http { server { alias "x"suffix; } }',b'http { server { \x00; } }',b'http { server { \xff; } }',b'http {} }',b'http { ; }']:
            self.assertEqual(self.check(data)['status'],'OPEN')

    def test_nonhttp_fragments_never_clean(self):
        for data in [b'location / { alias /private/; }',b'stream { server {} }',b'unknown private;',b'events {}']:
            self.assertEqual(self.check(data)['status'],'OPEN')

    def test_positions_are_physical_byte_locations(self):
        data=b'# private\nhttp {\n server {\n location /x {\n alias /private/;\n } } }'
        r=self.expect('alias_prefix_boundary',data,'FAIL')
        p=next(f['position'] for f in r['findings'] if f['code']=='alias_prefix_boundary')
        self.assertEqual(p,{'byte_offset':data.index(b'alias'),'line':5,'byte_column':2})

    def test_private_values_arbitrary_names_and_exception_paths_not_emitted(self):
        data=config('set $private_identifier private_secret; alias /private_target/; return 200 private_body;',prefix='/private_location')
        text=json.dumps(self.check(data))
        for secret in ['private_identifier','private_secret','private_target','private_body','private_location']:
            self.assertNotIn(secret,text)
        with mock.patch('nginx_config_guard.report.os.open',side_effect=OSError('private_exception_secret')):
            r=review_config('private-input-path')
        self.assertNotIn('private_exception_secret',json.dumps(r));self.assertNotIn('private-input-path',json.dumps(r))

    def test_files_urls_symlinks_fifo_and_directory_rejected(self):
        fifo=self.root/'fifo';os.mkfifo(fifo)
        link=self.root/'link';self.path.write_bytes(config());link.symlink_to(self.path)
        for path in ['-', '@private-list','https://private.invalid/config',str(self.root),str(self.root/'absent'),str(link),str(fifo)]:
            r=review_config(path);self.assertEqual(r['status'],'OPEN',r)
            if len(path)>1:self.assertNotIn(path,json.dumps(r))

    def test_all_budgets_retain_open(self):
        cases=[('input_limit',config(),dict(input_bytes=10)),('token_limit',config(),dict(tokens=2)),('token_bytes',config(),dict(token_bytes=2)),('argument_limit',config('proxy_set_header A B C;'),dict(arguments=1)),('node_limit',config(),dict(nodes=2)),('scope_limit',config(),dict(scopes=2)),('nesting_limit',config(),dict(nesting=2)),('variable_limit',config('set $a fixed; set $b fixed;'),dict(variables=1)),('map_limit',config('',http='map $arg_x $target { default fixed; key other; }'),dict(map_entries=1)),('alternative_limit',config('proxy_pass http://$target/;',http='map $arg_x $target { default fixed; key other; }'),dict(alternatives=1)),('model_limit',config(),dict(model_steps=1)),('expansion_bytes',config('set $a "'+('x'*60)+'"; set $b $a$a; proxy_pass http://$b/;'),dict(token_bytes=64))]
        for code,data,values in cases:
            with self.subTest(code=code):self.expect(code,data,limits=replace(Limits(),**values))

    def test_finding_and_report_limits_preserve_failure(self):
        r=self.check(config('alias /private/; '+('unknown private; '*8),prefix='/bad'),limits=replace(Limits(),findings=2))
        self.assertEqual(r['status'],'OPEN');self.assertIn('finding_limit',{f['code'] for f in r['findings']})
        body='allow 192.0.2.1; '+''.join('location /x'+str(i)+'/ {}' for i in range(50))
        r=self.check(config(body),limits=replace(Limits(),report_bytes=8192))
        self.assertEqual(r['status'],'FAIL');self.assertIn('report_limit',{f['code'] for f in r['findings']})
        self.assertTrue(any(f['status']=='FAIL' for f in r['findings']))

    def test_new_failure_at_findings_boundary_keeps_evidence_and_global_status(self):
        for unknowns, limit in [(1, Limits(findings=2)), (199, Limits())]:
            with self.subTest(unknowns=unknowns):
                data = config('alias /srv/static/;', prefix='/static',
                              server='unknown private; ' * unknowns)
                r = self.check(data, limits=limit)
                self.assertEqual(r['status'], 'FAIL')
                self.assertEqual(r['selected_rules']['alias_mapping'], 'FAIL')
                self.assertFalse(r['coverage_complete'])
                self.assertLessEqual(len(r['findings']), limit.findings)
                failure = next(f for f in r['findings'] if f['status'] == 'FAIL')
                self.assertEqual(failure['code'], 'alias_prefix_boundary')
                self.assertEqual(failure['position']['byte_offset'], data.index(b'alias'))
                self.assertIn('finding_limit', {f['code'] for f in r['findings']})

    def test_earlier_failure_survives_later_findings_boundary(self):
        from nginx_config_guard.report import Stop
        r = Report(Limits(findings=2))
        r.add('FAIL', 'first_failure', 'Fixed evidence.', rule='alias_mapping')
        with self.assertRaises(Stop):
            r.add('FAIL', 'second_failure', 'Later fixed evidence.', rule='allow_without_deny')
        result = r.finish()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(len(result['findings']), 2)
        self.assertEqual(result['findings'][0]['code'], 'first_failure')

    def test_limits_bad_types_raise_not_silent_defaults(self):
        for value in (0,False,'',{},[]):
            with self.assertRaises(TypeError):review_config(self.path,limits=value)
        for limit in [replace(Limits(),tokens=True),replace(Limits(),tokens=0),replace(Limits(),tokens=50001)]:
            with self.assertRaises(ValueError):review_config(self.path,limits=limit)

    def test_no_network_process_nginx_or_config_execution(self):
        with mock.patch.object(socket,'create_connection',side_effect=AssertionError('network')),mock.patch.object(urllib.request,'urlopen',side_effect=AssertionError('url')),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('process')):
            self.assertEqual(self.check()['status'],'PASS')
            self.expect('include_unexpanded',config('include private-path;'))

    def test_cli_statuses_and_removed_options(self):
        for data,code in [(config(),0),(config('allow 192.0.2.1;'),1),(config('include private-path;'),2)]:
            self.path.write_bytes(data)
            with mock.patch('sys.stdout',new_callable=io.StringIO) as output:
                self.assertEqual(main([str(self.path)]),code)
                self.assertEqual(json.loads(output.getvalue())['status'],{0:'PASS',1:'FAIL',2:'OPEN'}[code])
        for option in ['--regex-redos-url','--output','--plugins','--vars-dirs','--write-config','--include-root']:
            with mock.patch('sys.stdout',new_callable=io.StringIO) as output, mock.patch('sys.stderr',new_callable=io.StringIO) as error:
                self.assertEqual(main([str(self.path),option]),2)
            self.assertEqual(json.loads(output.getvalue())['status'],'OPEN')
            self.assertEqual(error.getvalue(),'')

    def test_cli_argument_errors_never_echo_private_values(self):
        for arguments in [[], [str(self.path), '--private-argument-marker'],
                          [str(self.path), 'private-extra-position'],
                          ['--output=private-report-path']]:
            with mock.patch('sys.stdout',new_callable=io.StringIO) as output, mock.patch('sys.stderr',new_callable=io.StringIO) as error:
                self.assertEqual(main(arguments), 2)
            text = output.getvalue()
            self.assertEqual(error.getvalue(), '')
            self.assertNotIn(str(self.path), text)
            for private in ('private-argument-marker', 'private-extra-position', 'private-report-path'):
                self.assertNotIn(private, text)
            report = json.loads(text)
            self.assertEqual(report['status'], 'OPEN')
            self.assertEqual(report['findings'][0]['code'], 'invalid_arguments')
            self.assertEqual(report['application_eligibility'], 'OPEN')


if __name__=='__main__':unittest.main()
