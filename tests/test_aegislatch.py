import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import Mock

from aegislatch import (ApprovalAuthority, AuditLedger, Gateway, Policy, PolicyError,
                       ToolCall, ToolDenied, digest)
from aegislatch.core import load_json_strict


class AegisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'allow'
        self.root.mkdir()
        (self.root / 'ok.txt').write_text('safe', encoding='utf8')
        self.policy = Policy({
            'version': 1, 'default': 'deny', 'rules': [
                {'id': 'file', 'principal': 'user', 'server': 'local', 'tool': 'read',
                 'effect': 'allow', 'resource': {'kind': 'file', 'arg': 'path', 'roots': ['allow']}},
                {'id': 'web', 'principal': 'user', 'server': 'remote', 'tool': 'post',
                 'effect': 'review', 'resource': {'kind': 'url', 'arg': 'url', 'hosts': ['api.example.org']}},
                {'id': 'shell', 'principal': 'user', 'server': 'local', 'tool': 'shell',
                 'effect': 'deny', 'resource': {'kind': 'none'}},
                {'id': 'schema', 'principal': 'user', 'server': 'local', 'tool': 'with_schema',
                 'effect': 'allow', 'resource': {'kind': 'none'},
                 'schema_sha256': digest({'name': 'with_schema', 'inputSchema': {'type': 'object'}})}
            ]}, self.base)

    def call(self, tool='read', server='local', **args):
        return ToolCall('user', server, tool, args)

    def test_explicit_file_allow(self):
        self.assertTrue(self.policy.evaluate(self.call(path=str(self.root / 'ok.txt'))).allowed)

    def test_deny_unknown_tools_and_identity(self):
        self.assertEqual(self.policy.evaluate(self.call(tool='unknown')).status, 'deny')
        self.assertEqual(self.policy.evaluate(ToolCall('other', 'local', 'read', {})).status, 'deny')

    def test_deny_traversal_and_prefix_confusion(self):
        outside = self.base / 'allow-more' / 'secret'
        outside.parent.mkdir()
        outside.write_text('private')
        self.assertEqual(self.policy.evaluate(self.call(path=str(outside))).status, 'deny')
        traversed = self.root / '..' / 'allow-more' / 'secret'
        self.assertEqual(self.policy.evaluate(self.call(path=str(traversed))).status, 'deny')

    def test_deny_symlink_escape(self):
        outside = self.base / 'outside.txt'
        outside.write_text('private')
        (self.root / 'link').symlink_to(outside)
        self.assertEqual(self.policy.evaluate(self.call(path=str(self.root / 'link'))).status, 'deny')

    def test_relative_paths_denied(self):
        self.assertEqual(self.policy.evaluate(self.call(path='allow/ok.txt')).status, 'deny')

    def test_review_hostname_allowlist(self):
        self.assertEqual(self.policy.evaluate(self.call('post', 'remote', url='https://api.example.org/foo')).status, 'review')
        for url in ('http://api.example.org', 'https://api.example.org.evil.test',
                    'https://user:pass@api.example.org', 'https://api.example.org:444',
                    'https://api.example.org/?token=x', 'https://127.0.0.1/',
                    'https://api.example.org/#section', 'https://API.EXAMPLE.ORG./'):
            with self.subTest(url=url):
                self.assertEqual(self.policy.evaluate(self.call('post', 'remote', url=url)).status, 'deny')

    def test_secret_patterns_denied(self):
        self.assertEqual(self.policy.evaluate(self.call(path=str(self.root/'ok.txt'),
                                           credentials={'password': 'example'})).status, 'deny')
        self.assertEqual(self.policy.evaluate(self.call(path=str(self.root/'ok.txt'),
                                           other='ghp_'+'x'*36)).status, 'deny')

    def test_bounded_data(self):
        self.assertEqual(self.policy.evaluate(self.call(path=str(self.root/'ok.txt'), x='a'*20000)).status, 'deny')
        self.assertEqual(self.policy.evaluate(self.call(path=str(self.root/'ok.txt'), bad=float('nan'))).status, 'deny')

    def test_schema_pinning(self):
        call = self.call('with_schema')
        good = {'name': 'with_schema', 'inputSchema': {'type': 'object'}}
        self.assertEqual(self.policy.evaluate(call).status, 'deny')
        self.assertEqual(self.policy.evaluate(call, trusted_schema={'fake': True}).status, 'deny')
        self.assertTrue(self.policy.evaluate(call, trusted_schema=good).allowed)

    def test_rule_misconfiguration_denied(self):
        with self.assertRaises(PolicyError):
            Policy({'version': 1, 'default': 'allow', 'rules': []})
        with self.assertRaises(PolicyError):
            Policy({'version': 1, 'default': 'deny', 'rules': [{'id':'a', 'principal': 'a'}]})
        with self.assertRaises(ValueError):
            load_json_strict('{"a":1,"a":2}')

    def test_denied_handler_is_not_called(self):
        fn = Mock()
        with self.assertRaises(ToolDenied):
            Gateway(self.policy).execute(self.call('shell', command='dangerous'), fn)
        fn.assert_not_called()

    def test_handler_only_called_when_allowed(self):
        fn = Mock(return_value='done')
        result = Gateway(self.policy).execute(self.call(path=str(self.root/'ok.txt')), fn)
        self.assertEqual(result, 'done')
        fn.assert_called_once()

    def test_approval_only_human_ticket_and_one_use(self):
        call = self.call('post', 'remote', url='https://api.example.org/messages', payload='hello')
        decision = self.policy.evaluate(call)
        key = secrets.token_bytes(32)
        authority = ApprovalAuthority(self.base/'approval.sqlite', key)
        gateway = Gateway(self.policy, approvals=authority)
        fn = Mock(return_value='sent')
        with self.assertRaises(ToolDenied):
            gateway.execute(call, fn)
        ticket = authority.issue_after_human_review(call, decision, approver='human')
        changed = self.call('post', 'remote', url='https://api.example.org/messages', payload='goodbye')
        with self.assertRaises(ToolDenied):
            gateway.execute(changed, fn, approval_ticket=ticket)
        self.assertEqual(gateway.execute(call, fn, approval_ticket=ticket), 'sent')
        with self.assertRaises(ToolDenied):
            gateway.execute(call, fn, approval_ticket=ticket)
        self.assertEqual(fn.call_count, 1)

    def test_approval_tamper(self):
        call = self.call('post', 'remote', url='https://api.example.org/test')
        decision = self.policy.evaluate(call)
        authority = ApprovalAuthority(self.base/'approval.sqlite', secrets.token_bytes(32))
        ticket = authority.issue_after_human_review(call, decision, approver='human')
        self.assertFalse(authority.consume(ticket[:-3]+'abc', call, decision))
        self.assertFalse(authority.consume('invalid.token', call, decision))

    def test_audit_integrity_and_tampering(self):
        path = self.base/'audit.log'
        ledger = AuditLedger(path, secrets.token_bytes(32))
        call = self.call('shell', command='example')
        ledger.append(call, self.policy.evaluate(call))
        self.assertTrue(ledger.verify())
        self.assertNotIn('example', path.read_text())
        path.write_text(path.read_text().replace('deny', 'allow'))
        self.assertFalse(ledger.verify())
        with self.assertRaises(ValueError):
            ledger.append(call, self.policy.evaluate(call))

    def test_invalid_ip_allowlist_fail_closed(self):
        for bad_host in ('127.0.0.1', '192.168.1.1', '169.254.169.254'):
            with self.subTest(host=bad_host):
                with self.assertRaises(PolicyError):
                    Policy({'version': 1, 'default': 'deny', 'rules': [
                        {'id': 'url', 'principal': 'u', 'server': 's', 'tool': 'fetch',
                         'effect': 'allow', 'resource': {'kind': 'url', 'arg': 'url', 'hosts': [bad_host]}}
                    ]})

    def test_protocol_host_tricks_fail_closed(self):
        for url in ('https://api.example.org@evil.test/path', 'https://api.example.org\\@evil.test/',
                    'file:///etc/passwd', 'https://api.example.org:0',
                    'https://api.example.org/?access_token=abc',
                    'https://api.example.org/%00\x00'):
            with self.subTest(url=url):
                self.assertEqual(self.policy.evaluate(self.call('post', 'remote', url=url)).status, 'deny')

    def test_malformed_input_blocks(self):
        self.assertEqual(self.policy.evaluate(ToolCall('', 'local', 'read', {})).status, 'deny')
        self.assertEqual(self.policy.evaluate(ToolCall('user', 'local', 'read', [] )).status, 'deny')
        self.assertEqual(self.policy.evaluate(self.call(path='a\x00b')).status, 'deny')
        self.assertEqual(self.policy.evaluate(self.call(path=str(self.root/'ok.txt'), x=set())).status, 'deny')

    def test_duplicate_policy_rules_rejected(self):
        data = {'version': 1, 'default': 'deny', 'rules': [
            {'id': x, 'principal': 'u', 'server': 's', 'tool': 't',
             'effect': 'allow', 'resource': {'kind': 'none'}} for x in ('a','b')]}
        with self.assertRaises(PolicyError):
            Policy(data)

    def test_bool_version_rejected(self):
        with self.assertRaises(PolicyError):
            Policy({'version': True, 'default': 'deny', 'rules': []})

    def test_review_ticket_not_accepted_for_different_tool(self):
        call = self.call('post', 'remote', url='https://api.example.org/x')
        authority = ApprovalAuthority(self.base/'approval.sqlite', secrets.token_bytes(32))
        ticket = authority.issue_after_human_review(call, self.policy.evaluate(call), approver='verified')
        not_review = self.call('shell')
        self.assertFalse(authority.consume(ticket, not_review, self.policy.evaluate(not_review)))

    def test_approval_invalid_signing_key_and_ttl(self):
        with self.assertRaises(ValueError):
            ApprovalAuthority(self.base/'approval.sqlite', b'weak')
        authority = ApprovalAuthority(self.base/'approval.sqlite', secrets.token_bytes(32))
        call = self.call('post', 'remote', url='https://api.example.org/test')
        decision = self.policy.evaluate(call)
        with self.assertRaises(ValueError):
            authority.issue_after_human_review(call, decision, approver='human', ttl_seconds=301)
        with self.assertRaises(ValueError):
            authority.issue_after_human_review(call, decision, approver='human', ttl_seconds=True)
        with self.assertRaises(ValueError):
            authority.issue_after_human_review(call, decision, approver='')

    def test_audit_key_mismatch_denied(self):
        path = self.base/'audit.log'
        key = secrets.token_bytes(32)
        ledger = AuditLedger(path, key)
        call = self.call('shell')
        ledger.append(call, self.policy.evaluate(call))
        with self.assertRaises(ValueError):
            AuditLedger(path, secrets.token_bytes(32))

    def test_approval_rejects_different_database(self):
        call = self.call('post', 'remote', url='https://api.example.org/test')
        decision = self.policy.evaluate(call)
        key = secrets.token_bytes(32)
        authority_one = ApprovalAuthority(self.base/'one.sqlite', key)
        authority_two = ApprovalAuthority(self.base/'two.sqlite', key)
        ticket = authority_one.issue_after_human_review(call, decision, approver='human')
        self.assertFalse(authority_two.consume(ticket, call, decision))
        self.assertTrue(authority_one.consume(ticket, call, decision))

    def test_policy_no_network_or_filesystem_execution(self):
        # Policy evaluation alone must only return a decision, not run the command.
        denied = self.policy.evaluate(self.call('shell', command='touch /tmp/insecure'))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.rule_id, 'shell')

if __name__ == '__main__':
    unittest.main()
