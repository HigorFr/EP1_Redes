from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import json
import logging


#Particularmente a parte que eu mais gostei de mexer
    #Usamos o GPT para enetender como funciona criptografia básica e usamos aqui
    #A main cria uma chave pública a cada sessão, e depois compartilha com o servidor
    #Quem desafia pega a chave pública e o ip (pelo server)
    # Depois disso a comunicação fica entre eles, a única mensagem não criptografada enviada é a chave pública de quem está desafiando para o desafiado
    #A partir daí eles já realizam a operação para criar o segredo compartilhado entre eles
    #Então eles passam a mensagem por um AESGCM e está feito. Quando chega é só descriptografar

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