import socket
import threading
import json
import sys
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
UDP_BROADCAST_PORT = 5001

MOVES = {
    "Tackle": 15,
    "Thunderbolt": 25,
    "QuickAttack": 12,
    "Flamethrower": 25,
}

class Cryptografia:
    def __init__(self):
        self.sk = x25519.X25519PrivateKey.generate()
        self.pk = self.sk.public_key()

    def pk_base64(self):
        pk_bytes = self.pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(pk_bytes).decode()

    def shared_key(self, opp_pk_b64):
        opp_pk_bytes = base64.b64decode(opp_pk_b64)
        opp_pk = x25519.X25519PublicKey.from_public_bytes(opp_pk_bytes)
        return self.sk.exchange(opp_pk)

    @staticmethod
    def criptografar_json(shared_key, plaintext):
        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, json.dumps(plaintext).encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()

    @staticmethod
    def descriptografar_json(shared_key, ciphertext_b64):
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce, ciphertext = ciphertext[:12], ciphertext[12:]
            aesgcm = AESGCM(shared_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode())
        except Exception as e:
            print(f"[ERRO] Falha ao descriptografar: {e}")
            return None


class Rede:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def udp_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", UDP_BROADCAST_PORT))
            while True:
                data, _ = s.recvfrom(4096)
                try:
                    msg = json.loads(data.decode())
                    print(f"[BCAST] {msg}")
                except Exception:
                    pass

    def udp_broadcast(self, msg: dict):
        data = json.dumps(msg).encode()
        self.sock.sendto(data, ("255.255.255.255", UDP_BROADCAST_PORT))

    def p2p_listener(self, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(1)
        listener.settimeout(10)
        conn, addr = listener.accept()
        listener.close()
        print(f"[P2P] Conectado com {addr}")
        return conn

    def p2p_dial(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        print(f"[P2P] Conectado a {(ip, port)}")
        return s

    @staticmethod
    def send_p2p(obj, p2p_file, shared_key):
        msg = Cryptografia.criptografar_json(shared_key, obj).encode()
        p2p_file.write(msg + b"\n")
        p2p_file.flush()

    @staticmethod
    def receive_p2p(p2p_file, shared_key):
        msg_cripto = p2p_file.readline().strip()
        return Cryptografia.descriptografar_json(shared_key, msg_cripto.decode())


class Servidor:
    @staticmethod
    def send_json(sock, obj):
        line = (json.dumps(obj) + "\n").encode()
        sock.sendall(line)

    @staticmethod
    def recv_json_line(sock):
        buf = b""
        while True:
            ch = sock.recv(1)
            if not ch:
                return None
            if ch == b"\n":
                break
            buf += ch
        try:
            return json.loads(buf.decode())
        except Exception:
            return None

    def register(self, name, p2p_port, pk_b64):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
        self.send_json(s, {
            "cmd": "REGISTER",
            "name": name,
            "p2p_port": p2p_port,
            "public_key": pk_b64
        })
        resp = self.recv_json_line(s)
        if not resp or resp.get("type") != "OK":
            print("Falha ao registrar:", resp)
            sys.exit(1)
        return s

    def request_match(self, sock, target=None):
        if target:
            self.send_json(sock, {"cmd": "CHALLENGE", "target": target})
        else:
            self.send_json(sock, {"cmd": "MATCH_RANDOM"})
        while True:
            resp = self.recv_json_line(sock)
            if not resp:
                return None
            if resp.get("type") == "MATCH":
                return resp["opponent"]
            elif resp.get("type") == "ERR":
                print("Erro:", resp)
                return None


class Batalha:
    class ContextoBatalha:
        def __init__(self, my_name, opp_name):
            self.my_name = my_name
            self.opp_name = opp_name
            self.my_hp = 100
            self.opp_hp = 100
            self.my_turn = False
            self.lock = threading.Lock()

        def apply_move(self, move_name, by_me):
            dmg = MOVES.get(move_name, 10)
            with self.lock:
                if by_me:
                    self.opp_hp = max(0, self.opp_hp - dmg)
                else:
                    self.my_hp = max(0, self.my_hp - dmg)

        def is_over(self):
            return self.my_hp <= 0 or self.opp_hp <= 0

        def winner(self):
            if self.my_hp <= 0 and self.opp_hp <= 0:
                return "draw"
            if self.my_hp <= 0:
                return self.opp_name
            if self.opp_hp <= 0:
                return self.my_name
            return None





    def __init__(self, my_name, my_p2p_port, opp_info, dial, rede, crypto, server_sock):
        self.state = self.ContextoBatalha(my_name, opp_info["name"])
        self.state.my_turn = dial
        self.rede = rede
        self.crypto = crypto
        self.server_sock = server_sock
        self.opp_info = opp_info
        self.my_p2p_port = my_p2p_port
        self.shared_key = None
        self.p2p_socket = None
        self.p2p_file = None

    def preparar_conexao(self, dial):
        if dial:
            self.p2p_socket = self.rede.p2p_dial(self.opp_info["ip"], int(self.opp_info["p2p_port"]))
        else:
            self.p2p_socket = self.rede.p2p_listener(self.my_p2p_port)

        self.p2p_file = self.p2p_socket.makefile("rwb")
        self.shared_key = self.crypto.shared_key(self.opp_info["public_key"])

        #Debug
        print("\nSeu seguredo compartilhado:" + self.shared_key + "\n")

    def loop(self):
        print(f"\n=== BATALHA INICIADA ===\n{self.state.my_name} vs {self.state.opp_name}")
        print("Seus movimentos:", ", ".join(MOVES.keys()))



        #Aqui começa o loop do jogo
        while not self.state.is_over():
            if self.state.my_turn:
                move = input("Seu movimento: ").strip().capitalize()
                if move not in MOVES:
                    print("Movimento inválido.")
                    continue

                self.rede.send_p2p({"type": "MOVE", "name": move}, self.p2p_file, self.shared_key)
                self.state.apply_move(move, True)
                print(f"Você usou {move}! HP do oponente: {self.state.opp_hp}")
                self.state.my_turn = False


            else:
                print("Aguardando movimento do oponente...")
                msg = self.rede.receive_p2p(self.p2p_file, self.shared_key)
                if not msg:
                    print("Conexão P2P encerrada.")
                    break
                opp_move = msg.get("name")
                self.state.apply_move(opp_move, False)
                print(f"Oponente usou {opp_move}! Seu HP: {self.state.my_hp}")
                self.state.my_turn = True



        vencedor = self.state.winner()
        print(f"\nResultado: {vencedor}")
        Servidor.send_json(self.server_sock, {
            "cmd": "RESULT",
            "me": self.state.my_name,
            "opponent": self.state.opp_name,
            "winner": vencedor
        })



#main
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python client.py <meu_nome> <minha_porta_p2p>")
        sys.exit(1)

    my_name = sys.argv[1]
    my_p2p_port = int(sys.argv[2])

    rede = Rede()
    crypto = Cryptografia()
    servidor = Servidor()

    threading.Thread(target=rede.udp_listener, daemon=True).start()

    server_sock = servidor.register(my_name, my_p2p_port, crypto.pk_base64())

    while True:
            cmd = input("Digite comando (list, desafiar <nome>, aleatorio, sair): ").strip()
            if cmd == "list":
                servidor.send_json(server_sock, {"cmd": "LIST"})
                print("Jogadores online:", servidor.recv_json_line(server_sock))
            
            
            
            
            elif cmd.startswith("desafiar "):
                alvo = cmd.split(" ", 1)[1]
                if alvo == my_name:
                    print("Você não pode se desafiar.")
                    continue
                op = servidor.request_match(server_sock, alvo)
                batalha = Batalha(my_name, my_p2p_port, op, dial=False, rede=rede, crypto=crypto, server_sock=server_sock)
                batalha.preparar_conexao(dial=False)
                batalha.loop()
            elif cmd == "aleatorio":
                op = servidor.request_match(server_sock)
                batalha = Batalha(my_name, my_p2p_port, op, dial=False, rede=rede, crypto=crypto, server_sock=server_sock)
                batalha.preparar_conexao(dial=False)
                batalha.loop()
            elif cmd.startswith("aceitar "):
                alvo = cmd.split(" ", 1)[1]
                op = servidor.request_match(server_sock, alvo)
                batalha = Batalha(my_name, my_p2p_port, op, dial=True, rede=rede, crypto=crypto, server_sock=server_sock)
                batalha.preparar_conexao(dial=True)
                batalha.loop()
            
            
            
            elif cmd == "sair":
                print("Saindo...")
                break
            else:
                print("Comando inválido.")

    server_sock.close()
    print("Conexão encerrada.")