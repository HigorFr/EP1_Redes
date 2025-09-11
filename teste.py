from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# A e B já derivaram a mesma shared_key (32 bytes)


shared_key = os.urandom(32)  # simulação, no real vem do Diffie-Hellman
aesgcm = AESGCM(shared_key)
nonce = os.urandom(12)  
mensagem = b"Oi, tudo bem?"

ciphertext = aesgcm.encrypt(nonce, mensagem, None)
pacote = nonce + ciphertext


# --- Lado B (receptor) ---
aesgcm = AESGCM(shared_key)

nonce_recv = pacote[:12]
ciphertext_recv = pacote[12:]

msg_original = aesgcm.decrypt(nonce_recv, ciphertext_recv, None)

print("Mensagem recebida:", msg_original.decode())
