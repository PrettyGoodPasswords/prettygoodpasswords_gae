#!/usr/bin/env python

# Copyright 2016
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import hashlib
import random
import string

import passwordmeter
from constants import SERVER_SALT
import most_common_pass

from os import urandom
from base64 import b64encode, b64decode
from itertools import izip

# Parameters to PBKDF2.
SALT_LENGTH = 12
DK_LEN = 16

# Linear to the hashing time. Adjust to be high but take a reasonable
# amount of time on your server. Measure with:
# python -m timeit -s 'import passwords as p' 'p.make_hash("something")'
COST_FACTOR = 100000

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'


# sufficiently pad the text to be encrypted
def pad(s):
    remainder = len(s) % BLOCK_SIZE
    if remainder > 0:
        return s + (BLOCK_SIZE - remainder) * PADDING
    return s


# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


def create_cipher(secret):
    """create a cipher object using the random secret
    """
    cipher = AES.new(secret)
    return cipher


def create_random_string(lenN):
    """generate N random digits from uppercase and numbers
    """
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(lenN))


def encode(text, cipher):
    """
    :param text: string to be encoded
    :param cipher: cipher object
    :return: encoded text
     encode/encypt text using the given cipher
     pads the text with entropy to align with the block size
    """
    lenEntropy = (BLOCK_SIZE - (len(text) % BLOCK_SIZE)) + BLOCK_SIZE - 2
    entropy = '{%s}' % create_random_string(lenEntropy)
    encoded = EncodeAES(cipher, text + entropy)
    return encoded


def decode(text, cipher):
    """
    :param text: string to decode
    :param cipher: cipher object
    :return: decoded text
    """
    decoded = DecodeAES(cipher, text)
    if decoded is not None and len(decoded) > 3 and decoded[-1] == '}':
        # then work to strip entropy string.
        # work backwards to the previous '{'
        iOpenBrace = len(decoded) - 1
        while iOpenBrace >= 0 and decoded[iOpenBrace] != '{':
            iOpenBrace -= 1
        if iOpenBrace >= 0:
            return decoded[:iOpenBrace]
    return decoded


def get_password_hash(password):
    """
    -- depricated --
    :param password: string password
    :return: generate a hash from a users password
    """
    hashed_password = hashlib.sha512(password + SERVER_SALT).hexdigest()
    return hashed_password


def make_pbkdf2_hash(password, cost=None, salt=None):
    """Generate a random salt and return a new hash for the password."""
    if isinstance(password, unicode):
        password = password.encode('utf-8')

    if salt is None:
        salt = urandom(SALT_LENGTH).encode('hex')
    elif isinstance(salt, unicode):
        salt = salt.encode('utf-8')

    if cost is None:
        cost = COST_FACTOR

    return cost, salt, PBKDF2(password, salt, dkLen=DK_LEN, count=COST_FACTOR).encode('hex')


def check_pbkdf2_hash(password, cost, salt, hash_a):
    """Check a password against an existing hash."""
    if isinstance(password, unicode):
        password = password.encode('utf-8')

    if isinstance(salt, unicode):
        salt = salt.encode('utf-8')

    hash_b = PBKDF2(password, salt, dkLen=DK_LEN, count=cost).encode('hex')
    if len(hash_a) != len(hash_b):
        return False

    # Same as "return hash_a == hash_b" but takes a constant time.
    # See http://carlos.bueno.org/2011/10/timing.html
    diff = 0
    for char_a, char_b in izip(hash_a, hash_b):
        diff |= ord(char_a) ^ ord(char_b)
    return diff == 0


def generate_key_from_pass(password):
    """
    -- depricated --
    :param password: string password
    :return: generate a cyptographic key from a users password
    """
    master_key = PBKDF2(password, SERVER_SALT, dkLen=16, count=10000)
    return master_key.encode('hex')


def elucidate_improvements(improvements):
    """
    :param improvements: dict return from  passwordmeter
    :return: convert suggestion dict to an array
    """
    arr = []
    for key, value in improvements.iteritems():
        arr.append(value)
    return arr


def check_password_strength(password):
    """
    :param password: string password
    :return: a float from 0-1.0 representing password strength,
    and an array of possible suggestions for how to improve
    """
    if most_common_pass.is_worst(password.lower()):
        return 0.00, ["This is one of the 10K most common passwords"]

    # meter = passwordmeter.Meter(settings=dict(factors =passwordmeter.DEFAULT_FACTORS))
    # strength, improvements = meter.test(password)
    strength, improvements = passwordmeter.test(password)
    return strength, elucidate_improvements(improvements)


def test_password_key():
    password = "terriblePassword"
    key = generate_key_from_pass(password)
    print "len(key)", len(key), key
    msg = "a little message"
    cipher = create_cipher(key)
    encoded = encode(msg, cipher)
    print 'encoded', encoded
    decoded = decode(encoded, cipher)
    print "decoded", decoded


def test_pbkdf2_password_hash():
    password = 'somethingElseThatShouldWork'
    print "generating hash"
    cost, salt, h = make_pbkdf2_hash(password)
    print "len(h)", len(h), h.encode('hex')
    print "salt", salt
    print "cost", cost
    print "checking hash"
    print check_pbkdf2_hash(password, cost, salt, h)


if __name__ == "__main__":
    print 'testing password hash'
    test_pbkdf2_password_hash()

    print 'testing password key generation'
    test_password_key()