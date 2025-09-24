import socket
import threading
import json
import sys
import base64
import os
import queue
import time
import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

BUFFER_SIZE = 4096


def input_default(prompt, default):
    s = input(f"{prompt}").strip()
    return s if s else default









MOVES = {
    "Tackle": 15,
    "Thunderbolt": 25,
    "QuickAttack": 12,
    "Flamethrower": 25,
    "HK": 100
}

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

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

class Network:
    def __init__(self, udp_broadcast_port):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_broadcast_port = udp_broadcast_port

    def start_udp_listener(self, handler):

        def _listen():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind(("0.0.0.0", self.udp_broadcast_port))
            logging.info(f"UDP listener rodando na porta {self.udp_broadcast_port}")

            logging.info(f"UDP listener rodando na porta {self.udp_broadcast_port}")
            while True:
                try:
                    data, addr = s.recvfrom(BUFFER_SIZE)
                    try:
                        msg = json.loads(data.decode())
                        handler(msg, addr)
                    except json.JSONDecodeError:
                        logging.debug("Recebeu UDP inválido")
                except Exception as e:
                    logging.exception("Erro no UDP listener: %s", e)
                    break
        t = threading.Thread(target=_listen, daemon=True)
        t.start()



    def udp_send(self, obj, ip='255.255.255.255', port=None):
        if port is None:
            port = self.udp_broadcast_port
        data = json.dumps(obj).encode()
        self.udp_sock.sendto(data, (ip, port))

    def p2p_listen(self, port, backlog=1, timeout=None):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(backlog)
        if timeout is not None:
            listener.settimeout(timeout)
        conn, addr = listener.accept()
        logging.info(f"P2P: conexão aceita {addr}")
        try:
            listener.close()
        except Exception:
            pass
        return conn

    def p2p_connect(self, ip, port, timeout=5.0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        logging.info(f"P2P: conectado a {(ip, port)}")
        s.settimeout(None)
        return s

    @staticmethod
    def send_line(sock, data):
        sock.sendall(data + b"\n")

    @staticmethod
    def recv_line(fileobj):
        line = fileobj.readline()
        if not line:
            return None
        return line.strip()


class ServerClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip 
        self.server_port = server_port

    @staticmethod
    def send_json(sock, obj):
        line = (json.dumps(obj) + "\n").encode()
        sock.sendall(line)

    @staticmethod
    def recv_json(sock):
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

    def register(self, name, p2p_port, pk_b64, udp_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server_ip, self.server_port))
        # adiciona udp_port no registro
        self.send_json(s, {
            "cmd": "REGISTER",
            "name": name,
            "p2p_port": p2p_port,
            "udp_port": udp_port,
            "public_key": pk_b64
        })
        resp = self.recv_json(s)
        if not resp or resp.get("type") != "OK":
            logging.error("Falha ao registrar no servidor: %s", resp)
            s.close()
            raise SystemExit(1)
        logging.info("Registrado no servidor com sucesso")
        return s
    



    def match(self, sock, target=None):
        if target:
            self.send_json(sock, {"cmd": "CHALLENGE", "target": target})
        else:
            self.send_json(sock, {"cmd": "MATCH_RANDOM"})
        while True:
            resp = self.recv_json(sock)
            if not resp:
                return None
            if resp.get("type") == "MATCH":
                return resp["opponent"]  # deve conter ip, p2p_port e udp_port
            if resp.get("type") == "ERR":
                logging.error("Erro do servidor: %s", resp)
                return None

class Battle:
    class State:
        def __init__(self, me, opp, turn):
            self.me = me
            self.opp = opp
            self.my_hp = 100
            self.opp_hp = 100
            self.my_turn = turn
            self.lock = threading.Lock()

        def apply_move(self, move, by_me):
            dmg = MOVES.get(move, 10)
            with self.lock:
                if by_me:
                    self.opp_hp = max(0, self.opp_hp - dmg)
                else:
                    self.my_hp = max(0, self.my_hp - dmg)

        def finished(self):
            return self.my_hp <= 0 or self.opp_hp <= 0

        def winner(self):
            if self.my_hp <= 0 and self.opp_hp <= 0:
                return "draw"
            if self.my_hp <= 0:
                return self.opp
            if self.opp_hp <= 0:
                return self.me
            return None

    def __init__(self, my_name, p2p_port, opp_info, dial, network, crypto, server_sock):
        self.state = Battle.State(my_name, opp_info['name'], dial)
        self.my_name = my_name
        self.p2p_port = p2p_port
        self.opp_info = opp_info
        self.dial = dial
        self.network = network
        self.crypto = crypto
        self.server_sock = server_sock
        self.shared_key = None
        self.conn = None
        self.fileobj = None

    def prepare(self):
        if self.dial:
            self.conn = self.network.p2p_connect(self.opp_info['ip'], int(self.opp_info['p2p_port']))


        else:
            self.conn = self.network.p2p_listen(self.p2p_port, backlog=1, timeout=10)
        self.fileobj = self.conn.makefile("rwb")
        self.shared_key = self.crypto.shared_key(self.opp_info['public_key'])
        logging.debug("Shared key criada com sucesso")

    def send_encrypted(self, obj):
        assert self.shared_key is not None
        msg = Crypto.encrypt_json(self.shared_key, obj).encode()
        Network.send_line(self.conn, msg)

    def recv_encrypted(self):
        assert self.shared_key is not None
        line = Network.recv_line(self.fileobj)
        if line is None:
            return None
        return Crypto.decrypt_json(self.shared_key, line.decode())

    def loop(self):
        logging.info(f"=== BATALHA: {self.state.me} vs {self.state.opp} ===")
        logging.info("Movimentos disponíveis: %s", ", ".join(MOVES.keys()))

        while not self.state.finished():
            try:                
                if self.state.my_turn:
                    move = input("Seu movimento: ").strip()
                    if move not in MOVES:
                        logging.info("Movimento inválido")
                        continue
                    self.send_encrypted({"type": "MOVE", "name": move})
                    self.state.apply_move(move, True)
                    logging.info(f"Você usou {move}. HP oponente: {self.state.opp_hp}")

                    self.state.my_turn = False
                else:
                    self.conn.settimeout(60.0)
                    logging.info("Aguardando movimento do oponente...")
                    msg = self.recv_encrypted()
                    if msg is None:
                        logging.warning("Conexão P2P encerrada")
                        break
                    if msg.get('type') == 'MOVE':
                        mv = msg.get('name')
                        self.state.apply_move(mv, False)
                        logging.info(f"Oponente usou {mv}. Seu HP: {self.state.my_hp}")
                        self.state.my_turn = True
            except:
                print("Timeout, saindo da batalha...")
                break
            finally:
                try:
                    self.conn.close()
                except Exception:
                    pass

        winner = self.state.winner()
        logging.info(f"Resultado da batalha: {winner}")
        ServerClient.send_json(self.server_sock, {"cmd": "RESULT", "me": self.state.me, "opponent": self.state.opp, "winner": winner})


class QueueManager:
    def __init__(self, my_name, p2p_port, network, crypto, server_sock, udp_port):
        self.my_name = my_name
        self.p2p_port = p2p_port
        self.network = network
        self.crypto = crypto
        self.server_sock = server_sock
        self.udp_port = udp_port  # usado como fallback no envio UDP
        self.enviados = {}
        self.recebidos = {}
        self.battle_started = threading.Event()

    def add_send(self, opp):
        desafio_id = f"{self.my_name}-{opp['name']}"
        q = queue.Queue()
        self.enviados[desafio_id] = q
        t = threading.Thread(target=self._process_send, args=(opp, q), daemon=True)
        t.start()

    def _process_send(self, opp, q):
        if self.battle_started.is_set():
            return

        op_name = opp['name']
        #usa a udp_port do oponente, se vier do servidor, ou tenta usar o proprio como padrão caso não venha
        dest_udp_port = opp.get('udp_port', self.udp_port)

        msg = {
            "type": "DES",
            "opponent": {
                "name": self.my_name,
                "ip": None,
                "udp_port": self.udp_port,
                "p2p_port": self.p2p_port,
                "public_key": self.crypto.public_key_b64()
            }
        }


        try:
            self.network.udp_send(msg, ip=opp.get('ip', '255.255.255.255'), port=dest_udp_port)
            
            logging.info("Desafio enviado para %s", op_name)
            print(opp.get('ip', '255.255.255.255'))
            print(dest_udp_port)

        except Exception as e:
            logging.error("Falha ao enviar desafio: %s", e)
            return
        try:
            resposta = q.get(timeout=20)
        except queue.Empty:
            logging.info("Timeout aguardando resposta de %s", op_name)
            return
        

        if self.battle_started.is_set():
            return
        if resposta and resposta.get('res') == 'ACE':
            logging.info("%s aceitou. Iniciando batalha (sou quem liga).", op_name)
            self.battle_started.set()
            b = Battle(self.my_name, self.p2p_port, opp, dial=True, network=self.network, crypto=self.crypto, server_sock=self.server_sock)
            b.prepare()
            b.loop()
            self.battle_started.clear()
        else:
            logging.info("%s recusou o desafio.", op_name)



    def receive_challenge(self, opp):
        logging.info("Desafio recebido de %s", opp['name'])
        opp["hora"] = time.time()
        self.recebidos[opp['name']] = opp




    def accept(self, opp_name):
        if opp_name not in self.recebidos:
            logging.info("Nenhum desafio de %s", opp_name)
            return
        
        #mudar, tem que apagar todo mundo
        opp = self.recebidos.pop(opp_name)


        if time.time() - opp["hora"] > 20:
            logging.info("Desafio de %s expirou", opp_name)
            return
        res = {"type": "RES", "opp": self.my_name, "res": "ACE"}
        
        
        self.network.udp_send(res, ip=opp.get('ip', '255.255.255.255'), port=opp.get('udp_port', self.udp_port))


        print("Enviado para:")
        print(opp.get('udp_port', '255.255.255.255'))

        print('\n')



        logging.info("Aceitei desafio de %s", opp_name)
        self.battle_started.set()
        b = Battle(self.my_name, self.p2p_port, opp, dial=False, network=self.network, crypto=self.crypto, server_sock=self.server_sock)
        try:
            b.prepare()
        except:
            return
        b.loop()
        self.battle_started.clear()

    def reject(self, opp_name):
        if opp_name not in self.recebidos:
            logging.info("Nenhum desafio de %s", opp_name)
            return
        opp = self.recebidos.pop(opp_name)
        res = {"type": "RES", "opp": self.my_name, "res": "NEG"}
        self.network.udp_send(res, ip=opp.get('ip', '255.255.255.255'), port=opp.get('udp_port', '255.255.255.255'))
        logging.info("Recusei desafio de %s", opp_name)

def main():

    # Nome do usuário
    print("Uso fácil: python client_refactor.py <meu_nome> <ip_server> <porta_server> <minha_porta_udp> <minha_porta_p2p>")

    my_name = sys.argv[1] if len(sys.argv) > 1 else input("Seu nome: ").strip()
    server_ip = sys.argv[2] if len(sys.argv) > 2 else input_default("IP do servidor (Vazio para 127.0.0.1)", "127.0.0.1")
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else int(input_default("Porta do servidor (Vazio para 5000)", "5000"))
    udp_port = int(sys.argv[4]) if len(sys.argv) > 4 else int(input_default("Porta UDP broadcast (Vazio para 5001)", "5001"))
    p2p_port = int(sys.argv[5]) if len(sys.argv) > 5 else int(input_default("Porta P2P (Vazio para 7000)", "7000"))

    network = Network(udp_broadcast_port=udp_port)
    crypto = Crypto()
    server = ServerClient(server_ip, server_port)

    def udp_handler(msg, addr):
        try:
            t = msg.get('type')
            if t == 'DES':
                opp = msg.get('opponent')
                opp['ip'] = addr[0]
                opp['porta'] = addr[1]
                queue_mgr.receive_challenge(opp)

            elif t == 'RES':
                opp_name = msg.get('opp')
                desafio_id = f"{my_name}-{opp_name}"
                q = queue_mgr.enviados.get(desafio_id)
                if q:
                    q.put(msg)

        except Exception:
            logging.exception("Erro tratando mensagem UDP")

    server_sock = server.register(my_name, p2p_port, crypto.public_key_b64(), udp_port)
    queue_mgr = QueueManager(my_name, p2p_port, network, crypto, server_sock, udp_port)
    network.start_udp_listener(udp_handler)

    try:
        while True:
            cmd = input("Digite comando (list, desafiar <nome>, aleatorio, aceitar <nome>, negar <nome>, sair): ").strip()
            if cmd == 'list':
                ServerClient.send_json(server_sock, {"cmd": "LIST"})
                resp = ServerClient.recv_json(server_sock)
                print(resp)
            elif cmd.startswith('desafiar '):
                alvo = cmd.split(' ', 1)[1]
                if alvo == my_name:
                    logging.info("Você não pode se desafiar")
                    continue
                opp = server.match(server_sock, target=alvo)
                if opp:
                    queue_mgr.add_send(opp)
            elif cmd == 'aleatorio':
                opp = server.match(server_sock)
                if opp:
                    queue_mgr.add_send(opp)
            elif cmd.startswith('aceitar '):
                nome = cmd.split(' ', 1)[1]
                queue_mgr.accept(nome)
            elif cmd.startswith('negar '):
                nome = cmd.split(' ', 1)[1]
                queue_mgr.reject(nome)
            elif cmd == 'sair':
                logging.info("Saindo...")
                break
            else:
                logging.info("Comando inválido")
    finally:
        try:
            server_sock.close()
        except Exception:
            pass

if __name__ == '__main__':
    main()
