# =============================
# FILE: client.py
# =============================

import socket
import threading
import json
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import base64
import os
import time ### NOVO ###

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
UDP_BROADCAST_PORT = 5001

MOVES = {
    "Tackle": 15,
    "Thunderbolt": 25,
    "QuickAttack": 12,
    "Flamethrower": 25,
}

class BattleState:
    def __init__(self, my_name, opp_name):
        self.my_name = my_name
        self.opp_name = opp_name
        self.my_hp = 100
        self.opp_hp = 100
        self.my_turn = False
        self.lock = threading.Lock()

    def apply_move(self, move_name, by_me: bool):
        dmg = MOVES.get(move_name, 10)
        with self.lock:
            if by_me:
                self.opp_hp = max(0, self.opp_hp - dmg)
            else:
                self.my_hp = max(0, self.my_hp - dmg)

    def is_over(self):
        with self.lock:
            return self.my_hp <= 0 or self.opp_hp <= 0

    def winner(self):
        if self.my_hp <= 0 and self.opp_hp <= 0:
            return "draw"
        if self.my_hp <= 0:
            return self.opp_name
        if self.opp_hp <= 0:
            return self.my_name
        return None

def udp_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", UDP_BROADCAST_PORT))
        while True:
            data, _ = s.recvfrom(4096)
            try:
                msg = json.loads(data.decode())
                if msg.get("type") == "EVENT":
                    print(f"\n[BCAST] {msg}\n> ", end="")
            except Exception:
                pass

### Função para enviar keepalives ###
def send_keepalive(sock):
    """
    Roda em uma thread separada para enviar mensagens periódicas ao servidor
    e manter a conexão viva.
    """
    while True:
        try:
            time.sleep(20) # Envia a cada 20 segundos
            send_json(sock, {"cmd": "KEEPALIVE"})
        except Exception:
            print("\n[CLIENT] Conexão com o servidor perdida. O programa será encerrado.")
            os._exit(1) # Força o encerramento do programa
            break

def send_json(sock, obj):
    line = (json.dumps(obj) + "\n").encode()
    sock.sendall(line)

def recv_json_line(sock):
    buf = b""
    while True:
        try:
            ch = sock.recv(1)
            if not ch:
                return None
            if ch == b"\n":
                break
            buf += ch
        except (ConnectionAbortedError, ConnectionResetError):
            return None # Retorna None se a conexão for fechada
    try:
        return json.loads(buf.decode())
    except Exception:
        return None

def register_with_server(name, p2p_port, pk_b64):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
    except ConnectionRefusedError:
        print("[CLIENT] Erro: Não foi possível conectar ao servidor. Verifique se ele está online.")
        sys.exit(1)
        
    send_json(s, {"cmd":"REGISTER", "name": name, "p2p_port": p2p_port, "public_key": pk_b64})
    resp = recv_json_line(s)
    if not resp or resp.get("type") != "OK":
        print("Falha ao registrar:", resp)
        sys.exit(1)
    
    print("[CLIENT] Registrado com sucesso no servidor.")
    return s

def request_match(sock, target=None):
    if target:
        send_json(sock, {"cmd":"CHALLENGE","target": target})
    else:
        send_json(sock, {"cmd":"MATCH_RANDOM"})

    # Não precisa de um loop aqui, o servidor responderá com MATCH ou ERR
    resp = recv_json_line(sock)
    if not resp:
        print("[CLIENT] Servidor encerrou a conexão.")
        return None
    
    if resp.get("type") == "MATCH":
        return resp["opponent"]
    elif resp.get("type") == "ERR":
        print("Erro do servidor:", resp.get("msg", "Erro desconhecido"))
        return None
    else:
        print("Resposta inesperada do servidor:", resp)
        return None

def p2p_listener(port, battle: BattleState):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(1)
    
    # Adicionamos um timeout para não ficar esperando para sempre
    listener.settimeout(20.0)
    try:
        conn, addr = listener.accept()
        print(f"[P2P] Conectado com {addr}")
        return conn
    except socket.timeout:
        print("[P2P] Nenhum jogador se conectou a tempo.")
        return None
    finally:
        listener.close()


def p2p_dial(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        print(f"[P2P] Conectado a {(ip, port)}")
        return s
    except Exception as e:
        print(f"[P2P] Falha ao se conectar ao oponente: {e}")
        return None

def battle_loop(p2p: socket.socket, battle: BattleState, server_sock: socket.socket, opp_pk , sk):
    opp_pk_bytes = base64.b64decode(opp_pk)
    opp_pk_obj = x25519.X25519PublicKey.from_public_bytes(opp_pk_bytes)
    shared_key = sk.exchange(opp_pk_obj)
    aesgcm = AESGCM(shared_key)
    
    p2p_file = p2p.makefile("rwb")

    def send_p2p(obj):
        nonce = os.urandom(12)
        line = (json.dumps(obj)).encode()
        cifrado = aesgcm.encrypt(nonce, line, None)
        msg_b64 = base64.b64encode(nonce + cifrado)
        msg = msg_b64 + b"\n"
        p2p_file.write(msg)
        p2p_file.flush()

    def receive_p2p():
        line_b64 = p2p_file.readline().strip()
        if not line_b64:
            return None
        try:
            line = base64.b64decode(line_b64)
            nonce = line[:12]
            dado = line[12:]
            decifrado = aesgcm.decrypt(nonce, dado, None)
            return json.loads(decifrado.decode())
        except Exception:
            return None

    print("\n=== BATALHA INICIADA ===")
    print(f"Você: {battle.my_name}  vs  Oponente: {battle.opp_name}")
    print("Seus movimentos:", ", ".join(MOVES.keys()))

    while not battle.is_over():
        if battle.my_turn:
            move = input("Seu movimento: ").strip()
            if move not in MOVES:
                print("Movimento inválido. Tente novamente.")
                continue
            send_p2p({"type":"MOVE","name": move})
            battle.apply_move(move, by_me=True)
            print(f"Você usou {move}! HP do oponente: {battle.opp_hp}")
            battle.my_turn = False
        else:
            print("Aguardando movimento do oponente...")
            msg = receive_p2p()
            if not msg:
                print("Oponente se desconectou.")
                break
            if msg.get("type") == "MOVE":
                opp_move = msg.get("name")
                battle.apply_move(opp_move, by_me=False)
                print(f"Oponente usou {opp_move}! Seu HP: {battle.my_hp}")
                battle.my_turn = True

    w = battle.winner()
    if w == "draw":
        print("Empate!")
    else:
        print("Vencedor:", w)
    send_json(server_sock, {"cmd":"RESULT","me": battle.my_name, "opponent": battle.opp_name, "winner": w})


def batalha_handler(my_name, my_p2p_port, sk, server_sock, op, dial):
    if not op:
        print("[CLIENT] Falha ao encontrar oponente.")
        return

    opp_name = op["name"]
    opp_ip = op["ip"]
    opp_port = int(op["p2p_port"])
    opp_pk = op["public_key"]

    battle = BattleState(my_name, opp_name)
    battle.my_turn = dial

    p2p_socket = None
    try:
        if dial:
            print("Aceitando desafio...")
            p2p_socket = p2p_dial(opp_ip, opp_port)
        else:
            print("Jogador Encontrado! Esperando oponente se conectar...")
            p2p_socket = p2p_listener(my_p2p_port, battle)

        if p2p_socket:
            battle_loop(p2p_socket, battle, server_sock, opp_pk, sk)
        else:
            print("Não foi possível estabelecer a conexão P2P para a batalha.")

    except Exception as e:
        print(f"Um erro ocorreu durante a batalha: {e}")
    finally:
        if p2p_socket:
            try:
                p2p_socket.close()
            except:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python client.py <meu_nome> <minha_porta_p2p>")
        sys.exit(1)

    my_name = sys.argv[1]
    my_p2p_port = int(sys.argv[2])

    threading.Thread(target=udp_listener, daemon=True).start()

    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    pk_b64 = base64.b64encode(pk_bytes).decode()

    server_sock = register_with_server(my_name, my_p2p_port, pk_b64)

    ### Inicia a thread de keepalive ###
    keepalive_thread = threading.Thread(target=send_keepalive, args=(server_sock,), daemon=True)
    keepalive_thread.start()
    
    while True:
        cmd = input("> ").strip()
        
        if not cmd:
            continue
        
        op = None

        if cmd == "list":
            send_json(server_sock, {"cmd": "LIST"})
            resp = recv_json_line(server_sock)
            if resp:
                print("Jogadores online:", resp.get("players", []))
            else:
                print("Não foi possível obter a lista de jogadores.")

        elif cmd.startswith("desafiar "):
            alvo = cmd.split(" ", 1)[1]
            if my_name == alvo:
                print("Você não pode se desafiar.")
                continue
            op = request_match(server_sock, alvo)
            batalha_handler(my_name, my_p2p_port, sk, server_sock, op, dial=False)
            
        elif cmd == "aleatorio":
            op = request_match(server_sock, None)
            batalha_handler(my_name, my_p2p_port, sk, server_sock, op, dial=False)
            
        elif cmd.startswith("aceitar "):
            alvo = cmd.split(" ", 1)[1]
            op = request_match(server_sock, alvo)
            batalha_handler(my_name, my_p2p_port, sk, server_sock, op, dial=True)

        elif cmd == "sair":
            print("Saindo...")
            break
        
        else:
            print("Comando inválido. Comandos: list, desafiar <nome>, aceitar <nome>, aleatorio, sair")

        if op:
            print("\n--- Batalha finalizada. Retornando ao menu principal. ---\n")

    server_sock.close()
    print("Conexão com o servidor encerrada.")