from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import json
import logging


class Crypto:
    def __init__(self):
        self._sk = x25519.X25519PrivateKey.generate()
        self._pk = self._sk.public_key()

    def public_key_b64(self):
        raw = self._pk.public_bytes(encoding=serialization.Encoding.Raw,
                                     format=serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def shared_key(self, opp_pk_b64):
        opp_raw = base64.b64decode(opp_pk_b64)
        opp_pk = x25519.X25519PublicKey.from_public_bytes(opp_raw)
        return self._sk.exchange(opp_pk)

    @staticmethod
    def encrypt_json(key, obj):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        plaintext = json.dumps(obj).encode()
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ct).decode()

    @staticmethod
    def decrypt_json(key, b64):
        try:
            raw = base64.b64decode(b64)
            nonce, ct = raw[:12], raw[12:]
            aesgcm = AESGCM(key)
            pt = aesgcm.decrypt(nonce, ct, None)
            return json.loads(pt.decode())
        except Exception as e:
            logging.warning(f"Falha ao descriptografar mensagem: {e}")
            return None