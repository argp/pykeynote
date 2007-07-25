#!/usr/bin/env python
# setup.py - Python extension module for KeyNote
# Copyright (c) 2007 Patroklos Argyroudis <argp at domain cs.tcd.ie>
#
# $Id$

# bootstrapping setuptools installer
from ez_setup import use_setuptools
use_setuptools()

# required modules
from setuptools import setup, Extension
import sys
import glob

# keynote is required
if glob.glob('/usr/lib/libkeynote.*'):
    keynote_module = Extension(name='keynote', sources=['keynote.c'],
            libraries=['keynote', 'crypto', 'm'])
elif glob.glob('%s/lib/libkeynote.*' % (sys.prefix)):
    keynote_module = Extension(name='keynote', sources=['keynote.c'],
            include_dirs=['%s/include' % (sys.prefix)],
            library_dirs=['%s/lib' % (sys.prefix)],
            libraries=['keynote', 'crypto', 'm'])
else:
    raise 'pykeynote requires keynote'

# compile the extension module
setup(name='keynote', version='1.0', author='Patroklos Argyroudis',
        author_email='argp at domain cs.tcd.ie',
        url='http://code.google.com/p/pykeynote/',
        description='KeyNote trust management system',
        long_description="""KeyNote credentials describe a specific delegation of trust and subsume the role of public key certificates; unlike traditional certificates, which bind keys to names, credentials can bind keys directly to the authorization to perform specific tasks.""",
        license='BSD',
        download_url='http://code.google.com/p/pykeynote/',
        ext_modules=[keynote_module])

# EOF
