# keynote.pyx - Python extension module for KeyNote
# Copyright (c) 2007 Patroklos Argyroudis <argp at domain cs.tcd.ie>
#
# $Id$

"""Python extension module for the KeyNote trust management system

This is a Python extension module for KeyNote.  It provides a
high-level object-oriented interface to the KeyNote trust management
API.  From the KeyNote web page:

  Trust management is a unified approach to specifying and
  interpreting security policies, credentials, and relationships; it
  allows direct authorization of security-critical actions.  KeyNote
  credentials describe a specific delegation of trust and subsume the
  role of public key certificates; unlike traditional certificates,
  which bind keys to names, credentials can bind keys directly to the
  authorization to perform specific tasks.

For more information, see RFC 2704, keynote(1), keynote(3), keynote(4)
and keynote(5).

Although pykeynote has been developed on Linux and minimally tested on
OpenBSD, it will probably work on all Unix-like systems that satisfy
the following requirements:

Python 2.3 or higher.

Pyrex (optional) version 0.9.4 or above available from:

http://www.cosc.canterbury.ac.nz/~greg/python/Pyrex/

The KeyNote trust management system (tested with version 2.3) available
from:

http://www1.cs.columbia.edu/~angelos/keynote.html

The OpenSSL cryptographic toolkit (tested with version 0.9.8d) available
from:

http://www.openssl.org/
"""

__author__ = 'Patroklos Argyroudis <argp at domain cs.tcd.ie>'
__copyright__ = 'Copyright (c) 2007 Patroklos Argyroudis'
__license__ = 'BSD'
__url__ = 'http://code.google.com/p/pykeynote/'
__version__ = '1.0'

cdef extern from "Python.h":
    int     PyList_Check(object pyo)
    int     PyFunction_Check(object pyo)
    int     PyList_Size(object pyo)
    int     PyString_Check(object pyo)
    char *  PyString_AsString(object pyo)
    object  PyString_FromStringAndSize(char *s, int len)
    object  PyCObject_FromVoidPtr(void *cobj, void (*destruct)(void*))
    void *  PyCObject_AsVoidPtr(object pyo)

cdef extern from *:
    char *  malloc(int size)
    void    free(void *p)

cdef extern from "regex.h":
    pass

cdef extern from "keynote.h":
    int keynote_errno

    struct keynote_deckey:
        int dec_algorithm
        void *dec_key

    struct keynote_keylist:
        int key_alg
        void *key_key
        char *key_stringkey
        keynote_keylist *key_next

    int     kn_init()
    int     kn_close(int sessid)
    int     kn_add_assertion(int sessid, char *assertion, int len,
                int flags)
    int     kn_remove_assertion(int sessid, int assertid)
    int     kn_remove_authorizer(int sessid, char *principal)
    int     kn_add_authorizer(int sessid, char *principal)
    int     kn_add_action(int sessid, char *name, char *value,
                int flags)
    int     kn_do_query(int sessid, char **returnvalues,
                int numvalues)
    int     kn_remove_action(int sessid, char *name)
    int     kn_cleanup_action_environment(int sessid)
    char *  kn_get_string(char *str)
    void *  kn_get_authorizer(int sessid, int assertid,
                int *algorithm)
    int     kn_verify_assertion(char *assertion, int len)
    char *  kn_sign_assertion(char *assertion, int len, char *key,
                char *algorithm, int vflag)
    char *  kn_encode_key(keynote_deckey *dc, int iencoding,
                int encoding, int keytype)
    int     kn_decode_key(keynote_deckey *dc, char *key, int keytype)
    int     kn_encode_hex(unsigned char *src, char **dst, int srclen)
    int     kn_decode_hex(char *src, char **dst)
    int     kn_encode_base64(unsigned char *src,
                unsigned int srclen, char *dst, unsigned int dstlen)
    int     kn_decode_base64(char *src, unsigned char *dst,
                unsigned int dstlen)
    int     kn_keycompare(void *key1, void *key2, int algorithm)
    int     kn_get_failed(int sessid, int type, int seq)
    keynote_keylist *   kn_get_licensees(int sessid, int assertid)

SIG_DSA_SHA1_HEX =                  "sig-dsa-sha1-hex:"
SIG_DSA_SHA1_HEX_LEN =              len(SIG_DSA_SHA1_HEX)
SIG_DSA_SHA1_BASE64 =               "sig-dsa-sha1-base64:"
SIG_DSA_SHA1_BASE64_LEN =           len(SIG_DSA_SHA1_BASE64)
SIG_RSA_SHA1_PKCS1_HEX =            "sig-rsa-sha1-hex:"
SIG_RSA_SHA1_PKCS1_HEX_LEN =        len(SIG_RSA_SHA1_PKCS1_HEX)
SIG_RSA_SHA1_PKCS1_BASE64 =         "sig-rsa-sha1-base64:"
SIG_RSA_SHA1_PKCS1_BASE64_LEN =     len(SIG_RSA_SHA1_PKCS1_BASE64)
SIG_RSA_MD5_PKCS1_HEX =             "sig-rsa-md5-hex:"
SIG_RSA_MD5_PKCS1_HEX_LEN =         len(SIG_RSA_MD5_PKCS1_HEX)
SIG_RSA_MD5_PKCS1_BASE64 =          "sig-rsa-md5-base64:"
SIG_RSA_MD5_PKCS1_BASE64_LEN =      len(SIG_RSA_MD5_PKCS1_BASE64)
SIG_ELGAMAL_SHA1_HEX =              "sig-elgamal-sha1-hex:"
SIG_ELGAMAL_SHA1_HEX_LEN =          len(SIG_ELGAMAL_SHA1_HEX)
SIG_ELGAMAL_SHA1_BASE64 =           "sig-elgamal-sha1-base64:"
SIG_ELGAMAL_SHA1_BASE64_LEN =       len(SIG_ELGAMAL_SHA1_BASE64)
SIG_PGP_NATIVE =                    "sig-pgp:"
SIG_PGP_NATIVE_LEN =                len(SIG_PGP_NATIVE)
SIG_X509_SHA1_HEX =                 "sig-x509-sha1-hex:"
SIG_X509_SHA1_HEX_LEN =             len(SIG_X509_SHA1_HEX)
SIG_X509_SHA1_BASE64 =              "sig-x509-sha1-base64:"
SIG_X509_SHA1_BASE64_LEN =          len(SIG_X509_SHA1_BASE64)

ENVIRONMENT_FLAG_FUNC =             0x0001
ENVIRONMENT_FLAG_REGEX =            0x0002

ASSERT_FLAG_LOCAL =                 0x0001
ASSERT_FLAG_SIGGEN =                0x0002
ASSERT_FLAG_SIGVER =                0x0004

SIGRESULT_UNTOUCHED =               0
SIGRESULT_FALSE =                   1
SIGRESULT_TRUE =                    2

KEYNOTE_ALGORITHM_UNSPEC =          -1
KEYNOTE_ALGORITHM_NONE =            0
KEYNOTE_ALGORITHM_DSA =             1
KEYNOTE_ALGORITHM_ELGAMAL =         2
KEYNOTE_ALGORITHM_PGP =             3
KEYNOTE_ALGORITHM_BINARY =          4
KEYNOTE_ALGORITHM_X509 =            5
KEYNOTE_ALGORITHM_RSA =             6

KEYNOTE_ERROR_ANY =                 0
KEYNOTE_ERROR_SYNTAX =              1
KEYNOTE_ERROR_MEMORY =              2
KEYNOTE_ERROR_SIGNATURE =           3

ENCODING_NONE =                     0
ENCODING_HEX =                      1
ENCODING_BASE64 =                   2
ENCODING_NATIVE =                   3

RESULT_FALSE =                      0
RESULT_TRUE =                       1

INTERNAL_ENC_NONE =                 0
INTERNAL_ENC_PKCS1 =                1
INTERNAL_ENC_ASN1 =                 2
INTERNAL_ENC_NATIVE =               3

KEYNOTE_PUBLIC_KEY =                0
KEYNOTE_PRIVATE_KEY =               1

KEYNOTE_VERSION_STRING =            "2"

ERROR_MEMORY =                      -1
ERROR_SYNTAX =                      -2
ERROR_NOTFOUND =                    -3
ERROR_SIGN_FAILURE =                -4

KEYNOTE_CALLBACK_INITIALIZE =       "_KEYNOTE_CALLBACK_INITIALIZE"
KEYNOTE_CALLBACK_CLEANUP =          "_KEYNOTE_CALLBACK_CLEANUP"

cdef class keynote:
    """keynote() -> A KeyNote session object

    Create a new KeyNote session object.
    """
    cdef int session
    cdef int keynote_errno
    cdef public object callbacks

    def __new__(self):
        self.session = kn_init()
        self.callbacks = []

        if self.session < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def close(self):
        """Close the session associated with the calling object.
        Note that this method should be called if you want any
        callback functions that may have been registered to be
        called with KEYNOTE_CALLBACK_CLEANUP.  Otherwise, the
        destructor is sufficient to correctly close the session.
        """
        self.__callback_cleanup()
        retval = kn_close(self.session)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def read_asserts(self, str):
        """Parse the given string and return a list of strings
        containing copies of the assertions found in the input.

        Arguments:
        str -- string containing assertions
        """
        assertions = []
        assertion = ''

        if str == '':
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        pos = str.find('\n')

        while pos >= 0:
            line = str[:pos + 1]
            str = str[pos + 1:]

            if line == '\n' or line == '':
                assertions.append(assertion)
                assertion = ''

            if line != '\n' and line != '':
                assertion = assertion + line

            pos = str.find('\n')

        # we don't want to lose the last line of str if it
        # does not end with '\n'
        if str != '\n' and str != '':
            assertion = assertion + str

        if assertion != '\n' and assertion != '':
            assertions.append(assertion)

        return assertions

    def verify_assertion(self, assertion):
        """Verify the cryptographic signature on the given
        assertion returning SIGRESULT_TRUE if the signature could be
        verified, or SIGRESULT_FALSE otherwise.

        Arguments:
        assertion -- string containing an assertion
        """
        retval = kn_verify_assertion(assertion, len(assertion))

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        return retval

    def sign_assertion(self, assertion, key,
            algorithm = SIG_RSA_SHA1_PKCS1_HEX, vflag = 0):
        """Produce and return the ASCII-encoded cryptographic
        signature for the given assertion using the given ASCII-encoded
        cryptographic private key.  The assertion is not modified.

        Arguments:
        assertion   -- string containing an unsigned assertion
        key         -- ASCII-encoded cryptographic private key
        algorithm   -- type of signature to be produced
        vflag       -- set to also verify the generated signature
        """
        cdef char *sig

        sig = kn_sign_assertion(assertion, len(assertion), key,
                algorithm, vflag)

        if sig == NULL:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_sig =  PyString_FromStringAndSize(sig, len(sig))
        free(sig)
        return obj_sig

    def add_assertion(self, assertion, flags = 0):
        """Add the given assertion to the current session, returning
        its assertion ID.

        Arguments:
        assertion   -- string containing an assertion
        flags       -- set to ASSERT_FLAG_LOCAL to mark the assertion
                       as ultimately trusted
        """
        retval = kn_add_assertion(self.session, assertion,
                len(assertion), flags)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        return retval

    def remove_assertion(self, assertid):
        """Remove the assertion identified by the given assertion ID
        from the current session.

        Arguments:
        assertid -- assertion ID (obtained from add_assertion())
        """
        retval = kn_remove_assertion(self.session, assertid)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def add_authorizer(self, principal):
        """Add the given principal to the action authorizers list of
        the current session.  The principal is typically an
        ASCII-encoded public key.

        Arguments:
        principal -- string containing a principal identifier
        """
        if principal == '':
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        retval = kn_add_authorizer(self.session, principal)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def remove_authorizer(self, principal):
        """Remove the given principal from the action authorizers list
        of the current session.

        Arguments:
        principal -- string containing a principal identifier
        """
        retval =  kn_remove_authorizer(self.session, principal)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def add_action(self, name, value, flags = 0):
        """Insert the given attribute name, value pair in the action
        environment of the current session.

        Arguments:
        name    -- attribute name
        value   -- attribute value
        flags   -- if set to ENVIRONMENT_FLAG_FUNC then the value must
                   be a function that takes as argument a string and
                   returns a string.  This is used to implement
                   callbacks for getting action attribute values.  If
                   it set to ENVIRONMENT_FLAG_REGEX then the name is
                   a regular expression that may match more than one
                   attribute.  The combination of the two flags is
                   allowed.  For more information see keynote(3).
        """
        if name == '' or value == '':
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        if flags & ENVIRONMENT_FLAG_FUNC:
            if PyFunction_Check(value) == False:
                self.keynote_errno = ERROR_SYNTAX
                raise keynote_error(self.keynote_errno)

            value(KEYNOTE_CALLBACK_INITIALIZE)
            self.callbacks.append((name, value, flags))
            return

        retval = kn_add_action(self.session, name, value, flags)
        
        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def remove_action(self, name):
        """Remove the specified action attribute from the environment
        of the current session.  If the attribute value was a callback,
        that function will be called with KEYNOTE_CALLBACK_CLEANUP as
        the argument.

        Arguments:
        name -- attribute name
        """
        retval = kn_remove_action(self.session, name)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def cleanup_action_environment(self):
        """Remove all action attributes from the action environment of
        the current session.
        """
        self.__callback_cleanup()
        retval = kn_cleanup_action_environment(self.session)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

    def get_string(self, str):
        """Parse the given quoted string and return its contents.
        Useful for parsing key files.

        Arguments:
        str -- quoted string
        """
        if str == '' or str[0] != '"' or str[-1] != '"':
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        retval = kn_get_string(str)
        return retval

    def get_authorizer(self, assertid):
        """Return a deckey object representing the authorizer key for
        the specified assertion of the current session.

        Arguments:
        assertid -- assertion ID (obtained from add_assertion())
        """
        cdef keynote_deckey dc

        dc.dec_key = kn_get_authorizer(self.session, assertid,
                &dc.dec_algorithm)

        if dc.dec_key == NULL:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_key = deckey(dc.dec_algorithm,
                PyCObject_FromVoidPtr(dc.dec_key, NULL))
        return obj_key

    def encode_key(self, dkey, iencoding = INTERNAL_ENC_PKCS1,
            encoding = ENCODING_HEX):
        """ASCII-encode and return a key contained in a deckey object.

        Arguments:
        dkey        -- a deckey object
        iencoding   -- describes how the key should be binary-encoded
        encoding    -- describes what ASCII encoding should be applied
                       to the deckey object
        """
        cdef char *key
        cdef keynote_deckey dc

        if isinstance(dkey, deckey) == False:
            raise ValueError, "deckey object expected"

        dc.dec_algorithm = dkey.algorithm
        dc.dec_key = PyCObject_AsVoidPtr(dkey.key)
        keytype = dkey.keytype
        
        key = kn_encode_key(&dc, iencoding, encoding, keytype)

        if key == NULL:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_key = PyString_FromStringAndSize(key, len(key))
        free(key)
        return obj_key

    def decode_key(self, key, key_type = KEYNOTE_PUBLIC_KEY):
        """Decode the given ASCII-encoded key returning a deckey
        object.

        Arguments:
        key     -- an ASCII-encoded key
        key_type -- KEYNOTE_PUBLIC_KEY or KEYNOTE_PRIVATE_KEY
        """
        cdef keynote_deckey dc

        if key == '':
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        retval = kn_decode_key(&dc, key, key_type)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_key = deckey(dc.dec_algorithm,
                PyCObject_FromVoidPtr(dc.dec_key, NULL),
                keytype=key_type)
        return obj_key

    def get_licensees(self, assertid):
        """Return the licensee key(s) for the given assertion ID of
        the current session as a list of one or more deckey object(s).

        Arguments:
        assertid -- assertion ID (obtained from add_assertion())
        """
        cdef keynote_keylist *kl
        key_list = []

        kl = kn_get_licensees(self.session, assertid)

        if kl == NULL:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        while kl != NULL:
            obj_key = deckey(kl.key_alg,
                    PyCObject_FromVoidPtr(kl.key_key, NULL),
                    PyString_FromStringAndSize(kl.key_stringkey,
                        len(kl.key_stringkey)))
            key_list.append(obj_key)
            kl = kl.key_next
        
        return key_list

    def keycompare(self, key1, key2):
        """Compare the two given deckey objects returning True if
        they are equal and False otherwise.

        Arguments:
        key1    -- deckey object
        key2    -- deckey object
        """
        if isinstance(key1, deckey) == False or isinstance(key2,
                deckey) == False:
            raise ValueError, "deckey objects expected"

        retval = kn_keycompare(PyCObject_AsVoidPtr(key1.key),
                PyCObject_AsVoidPtr(key2.key), key1.algorithm)

        if retval:
            return True
        else:
            return False

    def decode_hex(self, hex_str):
        """Decode the given ASCII hex-encoded string and return the
        result.  The length of the result will be (len(hex_str) / 2).

        Arguments:
        hex_str -- ASCII hex-encoded string
        """
        cdef char *dst
        cdef char *src

        if hex_str == '':
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        src = PyString_AsString(hex_str)
        retval = kn_decode_hex(src, &dst)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_str = PyString_FromStringAndSize(dst, len(hex_str) / 2)
        free(dst)
        return obj_str

    def encode_hex(self, bin_str, bin_len):
        """Encode in ASCII-hexadecimal format and return the given
        binary data of the given length.

        Arguments:
        bin_str -- binary data
        bin_len -- length of the binary data
        """
        cdef char *dst
        cdef unsigned char *src

        if bin_str == '' or bin_len <= 0:
           self.keynote_errno = ERROR_SYNTAX
           raise keynote_error(self.keynote_errno)

        src = <unsigned char *>PyString_AsString(bin_str)
        retval = kn_encode_hex(src, &dst, bin_len)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_str = PyString_FromStringAndSize(dst, len(dst))
        free(dst)
        return obj_str

    def encode_base64(self, bin_str, bin_len):
        """Encode in Base64 encoding and return the given binary data
        of the given length.

        Arguments:
        bin_str -- binary data
        bin_len -- length of the binary data
        """
        cdef char *dst
        cdef unsigned char *src

        if bin_str == '' or bin_len <= 0:
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        src = <unsigned char *>PyString_AsString(bin_str)
        dst = <char *>malloc(bin_len * 2 * sizeof(char))
        retval = kn_encode_base64(src, bin_len, dst, bin_len * 2)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_str = PyString_FromStringAndSize(dst, len(dst))
        free(dst)
        return obj_str

    def decode_base64(self, b64_str):
        """Decode the given ASCII Base64-encoded string and return the
        result.

        Arguments:
        b64_str -- ASCII Base64-encoded string
        """
        cdef unsigned char *dst
        cdef char *src

        if b64_str == '':
            self.keynote_errno = ERROR_SYNTAX
            raise keynote_error(self.keynote_errno)

        blen = 3 * (len(b64_str) / 4)
        src = PyString_AsString(b64_str)
        dst = <unsigned char *>malloc(blen * sizeof(unsigned char))
        retval = kn_decode_base64(b64_str, dst, blen)

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        obj_str = PyString_FromStringAndSize(<char *>dst, blen)
        free(dst)
        return obj_str

    def get_failed(self, type = KEYNOTE_ERROR_ANY, seq = 0):
        """Return the assertion ID in the current session that was
        somehow invalid during evaluation.

        Arguments:
        type    -- specifies the type of failure the application is
                   interested in
        seq     -- the number of the assertion (starting from zero)
        """
        retval = kn_get_failed(self.session, type, seq)
        return retval

    def do_query(self, retvalues):
        """Evaluate the request based on the assertions, action
        attributes, and action authorizers added to the current
        session.  The input is an ordered list of strings that
        contain the return values, and the return value is an index
        into the passed list.  The input list must be ordered from
        the lowest to the highest-ordered values.

        Arguments:
        retvalues -- ordered list of string that contain the return
                     values
        """
        cdef char **v
        cdef char **s
        cdef int size

        slist = retvalues

        if PyList_Check(slist):
            size = PyList_Size(slist)

            if size == 0:
                raise ValueError, "empty list"

            v = <char **>malloc(size * sizeof(char *))
            s = v

            for el in slist:
                if PyString_Check(el):
                    s[0] = el
                    s = s + 1
                else:
                     raise ValueError, "input list" \
                        "must contain strings"
        else:
            raise ValueError, "input not a list"

        # handle the callback functions
        for el in self.callbacks:
            (name, func, flags) = el
            val = func(name)
            flags = flags & ~ENVIRONMENT_FLAG_FUNC
            self.add_action(name, val, flags)

        retval = kn_do_query(self.session, v, size)
        free(v)

        for el in self.callbacks:
            (name, func, flags) = el
            try:
                self.remove_action(name)
            except:
                pass

        if retval < 0:
            self.keynote_errno = keynote_errno
            raise keynote_error(self.keynote_errno)

        return retval

    def __callback_cleanup(self):
        if len(self.callbacks) > 0:
            for el in self.callbacks:
                (name, func, flags) = el
                func(KEYNOTE_CALLBACK_CLEANUP)
                self.callbacks.remove(el)

    def __dealloc__(self):
        # __callback_cleanup() cannot be called here due to the way
        # Pyrex handles cdef classes
        kn_close(self.session)

cdef class deckey:
    """deckey() -> A deckey object

    Create a new deckey object for storing public/private key data.

    Arguments:
    algorithm   -- the key's cryptographic algorithm, can be
                   KEYNOTE_ALGORITHM_DSA, KEYNOTE_ALGORITHM_RSA, or
                   KEYNOTE_ALGORITHM_BINARY
    key         -- an object that stores a pointer to a binary key
    stringkey   -- ASCII-encoded representation of the binary key
    keytype     -- KEYNOTE_PUBLIC_KEY or KEYNOTE_PRIVATE_KEY
    """
    cdef keynote_deckey *dc
    cdef char *key_stringkey
    cdef int key_type

    def __new__(self, algorithm, key, stringkey = None,
            keytype = KEYNOTE_PUBLIC_KEY):
        self.dc = <keynote_deckey *>malloc(sizeof(keynote_deckey))
        self.dc.dec_algorithm = algorithm
        self.dc.dec_key = PyCObject_AsVoidPtr(key)
        self.key_type = keytype

        if stringkey != None:
            self.key_stringkey = PyString_AsString(stringkey)
        else:
            self.key_stringkey = NULL

    property algorithm:
        """Algorithm type (KEYNOTE_ALGORITHM_*) integer."""
        def __get__(self):
            return self.dc.dec_algorithm

    property key:
        """Object that stores a pointer to a binary key."""
        def __get__(self):
            return PyCObject_FromVoidPtr(self.dc.dec_key, NULL)

    property keytype:
        """Key type, i.e. public or private."""
        def __get__(self):
            return self.key_type

    property stringkey:
        """ASCII-encoded representation of the binary key."""
        def __get__(self):
            if self.key_stringkey == NULL:
                return None
            else:
                return PyString_FromStringAndSize(self.key_stringkey,
                        len(self.key_stringkey))

    def __dealloc__(self):
        if self.dc:
            free(self.dc)

class keynote_error(RuntimeError):
    """keynote_error() -> A KeyNote error exception object

    Create a new KeyNote error exception object.

    Arguments:
    knerrno -- keynote_errno integer
    """
    def __init__(self, knerrno):
        self.knerrno = knerrno

    def __str__(self):
        if self.knerrno == ERROR_MEMORY:
            return 'memory allocation or usage error'
        elif self.knerrno == ERROR_SYNTAX:
            return 'syntactic or logical error'
        elif self.knerrno == ERROR_NOTFOUND:
            return 'nonexistent structure or entry'
        else:
            return 'unknown error (%s)' % (self.knerrno)

# EOF
