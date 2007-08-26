#!/usr/bin/env python
# test.py - Python extension module for KeyNote
# Copyright (c) 2007 Patroklos Argyroudis <argp at domain cs.tcd.ie>
#
# $Id$

import sys
import glob
import unittest

sys.path.insert(0, glob.glob('./build/lib.*')[0])
import keynote

def load_test_assertions():
    file = open('./testsuite/root_policy', 'r')
    assert_str = file.read()
    assert_str += '\n'
    file.close()

    file = open('./testsuite/bob_policy', 'r')
    assert_str += file.read()
    assert_str += '\n'
    file.close()

    file = open('./testsuite/charles_policy', 'r')
    assert_str += file.read()
    assert_str += '\n'
    file.close()

    file = open('./testsuite/charles_policy_unsigned', 'r')
    assert_str += file.read()
    assert_str += '\n'
    file.close()

    return assert_str

def kn_callback(name):
    if name == keynote.KEYNOTE_CALLBACK_INITIALIZE:
        print 'kn_callback: KEYNOTE_CALLBACK_INITIALIZE'
    elif name == keynote.KEYNOTE_CALLBACK_CLEANUP:
        print 'kn_callback: KEYNOTE_CALLBACK_CLEANUP'
    else:
        return 'test_value'

class keynote_test(unittest.TestCase):
    def setUp(self):
        self.kn = keynote.keynote()
        self.failUnless(self.kn, 'error creating a new session')

    def tearDown(self):
        del self.kn

    def test_read_asserts(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        self.failUnless(len(assert_list) == 4)
        self.assertRaises(keynote.keynote_error,
                self.kn.read_asserts, '')

    def test_add_assertion(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        self.failUnless(self.kn.add_assertion(assert_list[0]) == 0)
        self.assertRaises(keynote.keynote_error,
                self.kn.add_assertion, '')

    def test_get_licensees(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[1])
        licensees = self.kn.get_licensees(assertion_id)
        self.failUnless(len(licensees) == 2)
        self.assertRaises(keynote.keynote_error,
                self.kn.get_licensees, 58)

    def test_remove_assertion(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[0])
        self.kn.remove_assertion(assertion_id)
        self.assertRaises(keynote.keynote_error,
                self.kn.remove_assertion, 58)

    def test_add_action(self):
        self.kn.add_action('test_name', 'test_value')
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, 'test_name', '')
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, '', 'test_value')
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, '_test', 'test_value')

    def test_add_action_regex(self):
        self.kn.add_action('[@$%_*]*[a-zA-Z0-9_]+', '0.2',
                keynote.ENVIRONMENT_FLAG_REGEX)
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, '[@$%_*]*[a-zA-Z0-9_]+', '',
                keynote.ENVIRONMENT_FLAG_REGEX)
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, '', '0.2',
                keynote.ENVIRONMENT_FLAG_REGEX)

    def test_get_failed(self):
        i = self.kn.get_failed()
        while i != -1:
            self.kn.remove_assertion(i)
            i = self.kn.get_failed()

    def test_add_action_func(self):
        self.kn.add_action('test_name', kn_callback,
                keynote.ENVIRONMENT_FLAG_FUNC)
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, '', kn_callback,
                keynote.ENVIRONMENT_FLAG_FUNC)
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, 'test_name', 'test_value',
                keynote.ENVIRONMENT_FLAG_FUNC)
        self.kn.close()

    def test_add_action_func_regex(self):
        self.kn.add_action('[@$%_*]*[a-zA-Z0-9_]+', kn_callback,
                keynote.ENVIRONMENT_FLAG_FUNC |
                keynote.ENVIRONMENT_FLAG_REGEX)
        self.assertRaises(keynote.keynote_error,
                self.kn.add_action, '^(\d{3})-(\d{3})-(\d{4})$',
                    'test_value', keynote.ENVIRONMENT_FLAG_FUNC |
                    keynote.ENVIRONMENT_FLAG_REGEX)
        self.kn.close()

    def test_remove_action(self):
        self.kn.add_action('test_name', 'test_value')
        self.kn.remove_action('test_name')
        self.assertRaises(keynote.keynote_error,
                self.kn.remove_action, '')
        self.assertRaises(keynote.keynote_error,
                self.kn.remove_action, 'nonexistent action')

    def test_verify_assertion(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        self.failUnless(self.kn.verify_assertion(assert_list[2]) ==
                keynote.SIGRESULT_TRUE)
        self.assertRaises(keynote.keynote_error,
                self.kn.verify_assertion, '')

    def test_sign_assertion(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        file = open('./testsuite/bob_private')
        private_key = file.read()
        file.close()

        self.failUnless(self.kn.sign_assertion(assert_list[3],
                    private_key) != '')
        self.failUnless(self.kn.sign_assertion(assert_list[3],
                    private_key, keynote.SIG_RSA_SHA1_PKCS1_BASE64, 1) != '')

        self.assertRaises(keynote.keynote_error,
                self.kn.sign_assertion, assert_list[3], '')
        self.assertRaises(keynote.keynote_error,
                self.kn.sign_assertion, '', private_key)
        self.assertRaises(keynote.keynote_error,
                self.kn.sign_assertion, '', '')

    def test_get_string(self):
        str = '"test"'
        invalid_str = 'test'
        self.failUnless(self.kn.get_string(str) == 'test')
        self.assertRaises(keynote.keynote_error,
                self.kn.get_string, '')
        self.assertRaises(keynote.keynote_error,
                self.kn.get_string, invalid_str)

    def test_cleanup_action_environment(self):
        self.kn.cleanup_action_environment()

    def test_do_query(self):
        return_values = ['false', 'true']
        test_values = []

        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        self.kn.add_assertion(assert_list[0],
                keynote.ASSERT_FLAG_LOCAL)
        self.kn.add_assertion(assert_list[1])
        assertion_id = self.kn.add_assertion(assert_list[2])
        authorizers = self.kn.get_licensees(assertion_id)
        self.kn.add_authorizer(authorizers[0].stringkey)
        self.kn.add_action('app_domain', 'pykeynote testsuite')
        self.kn.add_action('file_name', 'test_file')
        self.kn.add_action('operation', 'read')
        self.kn.add_action('other_attribute', 'other_value')
        pcv = self.kn.do_query(return_values)
        self.failUnless(return_values[pcv] == 'true')
        self.assertRaises(ValueError, self.kn.do_query, '')
        self.assertRaises(ValueError, self.kn.do_query, test_values)

    def test_get_authorizer(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[1])
        dc = self.kn.get_authorizer(assertion_id)
        self.failUnless(isinstance(dc, keynote.deckey))
        self.assertRaises(keynote.keynote_error,
                self.kn.get_authorizer, 58)

    def test_encode_key(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        dc = self.kn.get_authorizer(assertion_id)
        self.kn.encode_key(dc)
        self.assertRaises(ValueError, self.kn.encode_key, '')

    def test_decode_hex(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        dc = self.kn.get_authorizer(assertion_id)
        key_str = self.kn.encode_key(dc)
        self.kn.decode_hex(key_str)
        self.assertRaises(keynote.keynote_error, self.kn.decode_hex, '')

    def test_encode_hex(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        dc = self.kn.get_authorizer(assertion_id)
        key_str = self.kn.encode_key(dc)
        bin_key = self.kn.decode_hex(key_str)
        self.kn.encode_hex(bin_key, len(key_str) / 2)
        self.assertRaises(keynote.keynote_error, self.kn.encode_hex, '',
                len(key_str) / 2)
        self.assertRaises(keynote.keynote_error, self.kn.encode_hex, bin_key, 0)
        self.assertRaises(keynote.keynote_error, self.kn.encode_hex, '', 0)

    def test_encode_base64(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        dc = self.kn.get_authorizer(assertion_id)
        key_str = self.kn.encode_key(dc)
        bin_key = self.kn.decode_hex(key_str)
        self.kn.encode_base64(bin_key, len(key_str) / 2)
        self.assertRaises(keynote.keynote_error,
                self.kn.encode_base64, '', len(key_str) / 2)
        self.assertRaises(keynote.keynote_error,
                self.kn.encode_base64, bin_key, -1)
        self.assertRaises(keynote.keynote_error,
                self.kn.encode_base64, '', -2)

    def test_decode_base64(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        dc = self.kn.get_authorizer(assertion_id)
        key_str = self.kn.encode_key(dc)
        bin_key = self.kn.decode_hex(key_str)
        b64_key = self.kn.encode_base64(bin_key, len(key_str) / 2)
        self.kn.decode_base64(b64_key)
        self.assertRaises(keynote.keynote_error,
                self.kn.decode_base64, '')

    def test_decode_key(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        dc = self.kn.get_authorizer(assertion_id)
        key_str = self.kn.encode_key(dc)

        # we know this since RSA and hex encoding are the
        # defaults of encode_key()
        full_key = 'rsa-hex:%s' % (key_str)

        dc = self.kn.decode_key(full_key)
        self.failUnless(isinstance(dc, keynote.deckey))
        self.assertRaises(keynote.keynote_error, self.kn.decode_key, '')

    def test_keycompare(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        dc2 = self.kn.get_authorizer(assertion_id)
        assertion_id = self.kn.add_assertion(assert_list[1])
        dc1 = self.kn.get_authorizer(assertion_id)
        self.failUnless(self.kn.keycompare(dc1, dc2) == False)
        self.assertRaises(ValueError, self.kn.keycompare, '', dc2)
        self.assertRaises(ValueError, self.kn.keycompare, '', '')
        dc3 = self.kn.get_authorizer(assertion_id)
        self.failUnless(self.kn.keycompare(dc1, dc3) == True)

    def test_add_authorizer(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        licensees = self.kn.get_licensees(assertion_id)
        self.kn.add_authorizer(licensees[0].stringkey)
        self.assertRaises(keynote.keynote_error,
                self.kn.add_authorizer, '')

    def test_remove_authorizer(self):
        str = load_test_assertions()
        assert_list = self.kn.read_asserts(str)
        assertion_id = self.kn.add_assertion(assert_list[2])
        licensees = self.kn.get_licensees(assertion_id)
        self.kn.add_authorizer(licensees[0].stringkey)
        self.kn.remove_authorizer(licensees[0].stringkey)
        self.assertRaises(keynote.keynote_error,
                self.kn.remove_authorizer, 'nonexistent authorizer')
        self.assertRaises(keynote.keynote_error,
                self.kn.remove_authorizer, '')

if __name__ == '__main__':
    unittest.main()

# EOF
