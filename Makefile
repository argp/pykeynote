# Makefile - Python extension module for KeyNote
# Copyright (c) 2007 Patroklos Argyroudis <argp at domain cs.tcd.ie>
#
# $Id$

all:	keynote.c egg
	python setup.py build

keynote.c:	keynote.pyx
	pyrexc keynote.pyx

install:
	python setup.py install

uninstall:
	rm -rf /usr/lib/python2.3/site-packages/keynote*
	rm -rf /usr/lib/python2.4/site-packages/keynote*
	rm -rf /usr/lib/python2.5/site-packages/keynote*

test:
	python test.py

egg:
	python setup.py bdist_egg

doc:
	epydoc -o doc -n keynote \
		-u http://code.google.com/p/pykeynote/ \
		--docformat=plaintext keynote

sample:
	python sample_app.py

clean:
	python setup.py clean
	rm -rf build dist keynote.egg-info doc
	rm -rf *.pyc

distclean:	clean
	rm -f keynote.c

# EOF
