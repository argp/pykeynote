#!/usr/bin/env python
# sample_app.py - Python extension module for KeyNote
# Copyright (c) 2007 Patroklos Argyroudis <argp at domain cs.tcd.ie>
#
# $Id$

import glob
import sys

sys.path.insert(0, glob.glob('./build/lib.*')[0])
import keynote

file = open('./testsuite/root_policy', 'r')
root_policy = file.read()
file.close()

file = open('./testsuite/bob_policy', 'r')
bob_policy = file.read()
file.close()

file = open('./testsuite/charles_policy', 'r')
charles_policy = file.read()
file.close()

return_values = ['false', 'true']

try:
    kn = keynote.keynote()
except keynote.keynote_error, str:
    print str

try:
    kn.add_assertion(root_policy, keynote.ASSERT_FLAG_LOCAL)
    kn.add_assertion(bob_policy)
    assertion_id = kn.add_assertion(charles_policy)
    authorizers = kn.get_licensees(assertion_id)
    kn.add_authorizer(authorizers[0].stringkey)

    kn.add_action('app_domain', 'pykeynote testsuite')
    kn.add_action('file_name', 'test_file')
    kn.add_action('operation', 'read')
    kn.add_action('other_attribute', 'other_value')

    pcv = kn.do_query(return_values)
except keynote.keynote_error, str:
    print str

print 'final result = %s' % (return_values[pcv])

# find all syntax errors
i = kn.get_failed(keynote.KEYNOTE_ERROR_SYNTAX)
while i != -1:
    print 'syntax error in assertion %d' % (i)
    kn.remove_assertion(i)
    i = kn.get_failed(keynote.KEYNOTE_ERROR_SYNTAX)

# find all signature errors
i = kn.get_failed(keynote.KEYNOTE_ERROR_SIGNATURE)
while i != -1:
    print 'signature error in assertion %d' % (i)
    kn.remove_assertion(i)
    i = kn.get_failed(keynote.KEYNOTE_ERROR_SIGNATURE)

# find all errors
i = kn.get_failed()
while i != -1:
    print 'unspecified error in assertion %d' % (i)
    kn.remove_assertion(i)
    i = kn.get_failed()

try:
    kn.cleanup_action_environment() # optional

    # this should be called in order to call the registered
    # callback functions with KEYNOTE_CALLBACK_CLEANUP
    kn.close()
except keynote.keynote_error, str:
    print str

# EOF
