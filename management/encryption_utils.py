# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 256-bit key - this will be derived from the api key
key = None

def init(password):
	''' one-time initialization '''
	salt = password[-8:].encode('utf8')
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32, # 256 bits
		salt=salt,
		iterations=100000
	)
	global key
	key = kdf.derive(password[0:-8].encode('utf8'))

def iv_size():
	return 16

def to_bytes(v):
	if isinstance(v, bytes):
		return v
	if isinstance(v, str) and hasattr(v, 'encode'):
		return v.encode('utf8')
	return v

def encrypt(plain_bytes, b64=True):
	assert key is not None
	iv = os.urandom(iv_size())
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
	encryptor = cipher.encryptor()
	ct = iv + encryptor.update(to_bytes(plain_bytes)) + encryptor.finalize()
	if b64:
		enc = base64.urlsafe_b64encode(ct).decode('ascii')
		return enc
	else:
		return ct

def decrypt(crypt_bytes, b64=True):
	assert key is not None
	if b64:
		crypt_bytes = base64.urlsafe_b64decode(crypt_bytes)
	else:
		crypt_bytes = to_bytes(crypt_bytes)
	iv = crypt_bytes[0:iv_size()]
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
	decryptor = cipher.decryptor()
	plain = decryptor.update(crypt_bytes[iv_size():]) + decryptor.finalize()
	return plain
