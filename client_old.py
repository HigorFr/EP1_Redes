import socket
import threading
import json
import sys
import base64
import os
import queue
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
        self.crypto = Cryptografia()
        

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


    def udp_especifico(self, msg: dict, ip, porta):
        data = json.dumps(msg).encode()
        self.sock.sendto(msg.encode(), (ip, porta))


    def p2p_listener(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", self.my_p2p_port))
        listener.listen(5)
        print(f"[P2P] Listener rodando na porta {self.my_p2p_port}")

        while True:
            try:
                conn, addr = listener.accept()
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except Exception:
                continue


    def _handle_client(self, conn):
        with conn:
            f = conn.makefile("rwb")
            while True:
                line = f.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode())
                except Exception:
                    continue

                # Ignorar novos desafios se já tem batalha
                if self.batalha_iniciada.is_set():
                    continue

                # Se é resposta de desafio enviado


                if msg.get("type") == "DES":
                    op = msg["opponent"]
                    GerenciadorFilas.adicionarFilaRecebeminto(op)


                if msg.get("type") == "RES":
                    desafio_id = f"{self.my_name}-{msg['opp']}"
                    if desafio_id in self.enviados:
                        self.enviados[desafio_id].put(msg)



    def p2p_listener_batalha(self, port):
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
    def enviar_p2p(obj, p2p_file, shared_key):
        msg = Cryptografia.criptografar_json(shared_key, obj).encode()
        p2p_file.write(msg + b"\n")
        p2p_file.flush()

    @staticmethod
    def receber_p2p(p2p_file, shared_key):
        msg_cripto = p2p_file.readline().strip()
        return Cryptografia.descriptografar_json(shared_key, msg_cripto.decode())







class Servidor:
    @staticmethod
    def enviar_json(sock, obj):
        line = (json.dumps(obj) + "\n").encode()
        sock.sendall(line)

    @staticmethod
    def receber_json(sock):
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

    def registrar(self, name, p2p_port, pk_b64):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
        self.enviar_json(s, {
            "cmd": "REGISTER",
            "name": name,
            "p2p_port": p2p_port,
            "public_key": pk_b64
        })
        resp = self.receber_json(s)
        if not resp or resp.get("type") != "OK":
            print("Falha ao registrar:", resp)
            sys.exit(1)
        return s

    def partida(self, sock, target=None):
        if target:
            self.enviar_json(sock, {"cmd": "CHALLENGE", "target": target})
        else:
            self.enviar_json(sock, {"cmd": "MATCH_RANDOM"})
        while True:
            resp = self.receber_json(sock)
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

        def aplicar_movimento(self, move_name, by_me):
            dmg = MOVES.get(move_name, 10)
            with self.lock:
                if by_me:
                    self.opp_hp = max(0, self.opp_hp - dmg)
                else:
                    self.my_hp = max(0, self.my_hp - dmg)

        def terminado(self):
            return self.my_hp <= 0 or self.opp_hp <= 0

        def vencedor(self):
            if self.my_hp <= 0 and self.opp_hp <= 0:
                return "draw"
            if self.my_hp <= 0:
                return self.opp_name
            if self.opp_hp <= 0:
                return self.my_name
            return None





    def __init__(self, my_name, my_p2p_port, opp_info, dial, rede, crypto, server_sock):
        self.state = self.ContextoBatalha(my_name, opp_info["name"])
        self.dial = dial
        self.state.my_turn = dial
        self.rede = rede
        self.crypto = crypto
        self.server_sock = server_sock
        self.opp_info = opp_info
        self.my_p2p_port = my_p2p_port
        self.shared_key = None
        self.p2p_socket = None
        self.p2p_file = None

    def preparar_conexao(self):
        if self.dial:
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
        while not self.state.terminado():
            if self.state.my_turn:
                move = input("Seu movimento: ").strip().capitalize()
                if move not in MOVES:
                    print("Movimento inválido.")
                    continue

                self.rede.send_p2p({"type": "MOVE", "name": move}, self.p2p_file, self.shared_key)
                self.state.aplicar_movimento(move, True)
                print(f"Você usou {move}! HP do oponente: {self.state.opp_hp}")
                self.state.my_turn = False


            else:
                print("Aguardando movimento do oponente...")
                msg = self.rede.receive_p2p(self.p2p_file, self.shared_key)
                if not msg:
                    print("Conexão P2P encerrada.")
                    break
                opp_move = msg.get("name")
                self.state.aplicar_movimento(opp_move, False)
                print(f"Oponente usou {opp_move}! Seu HP: {self.state.my_hp}")
                self.state.my_turn = True



        vencedor = self.state.vencedor()
        print(f"\nResultado: {vencedor}")
        Servidor.enviar_json(self.server_sock, {
            "cmd": "RESULT",
            "me": self.state.my_name,
            "opponent": self.state.opp_name,
            "winner": vencedor
        })




class GerenciadorFilas:
   
    def __init__(self, my_name, my_p2p_port, rede, crypto, server_sock):
        self.my_name = my_name
        self.my_p2p_port = my_p2p_port
        self.rede = rede
        self.crypto = crypto
        self.server_sock = server_sock
        self.enviados = {}
        self.recebidos = {}
        self.batalha_iniciada = threading.Event()

    def adicionar_envio(self, op):  
        desafio_id = f"{self.my_name}-{op['name']}"
        q = queue.Queue()
        self.enviados[desafio_id] = q 
        # Criar uma thread para enviar + aguardar resposta
        t = threading.Thread(target=self._processar_envio, args=(op,))
        t.daemon = True  # encerra thread junto com o programa
        t.start()

            
    def _processar_envio(self, op):
        """Thread que envia o desafio e aguarda resposta."""
        try:

            if self.batalha_iniciada.is_set():
                return 


            desafio_id = f"{self.my_name}-{op['name']}"
            q = self.enviados[desafio_id] 

            msg = json.dumps({"type": "DES", "opponent": {"name": self.my_name, "public_key": Cryptografia.pk_base64()} })





            self.rede.udp_especifico(msg, op["ip"], op["porta"])
            print(f"[DEBUG] Pedido de batalha enviado para {op}")

            # 2. Fica escutando pela resposta
            try:

                resposta = q.get(timeout=20)

            except queue.Empty:
                if self.batalha_iniciada.is_set():
                    return 
                print(f"[DEBUG] Timeout esperando resposta de {op}")
                return

            if self.batalha_iniciada.is_set():
                return 
 


            if resposta and resposta.get("res") == "ACE":
                print(f"[DEBUG] {op} aceitou o desafio! Iniciando batalha...")
                self.batalha_iniciada.set()
                self._iniciar_batalha(op, False)


            elif resposta and resposta.get("res") == "NEG":
                print(f"[DEBUG] {op} recusou o desafio.")


        except Exception as e:
            print(f"[ERRO] Falha ao processar envio para {op}: {e}")




    def _iniciar_batalha(self, op, dial):
        batalha = Batalha(self.my_name, self.my_p2p_port, op,
                          dial=dial, rede=self.rede,
                          crypto=self.crypto,
                          server_sock=self.server_sock)
        batalha.preparar_conexao()
        batalha.loop()





    def adicionarFilaRecebeminto(self,op):
            print("Batalha Recebida")
            self.recebidos[op["name"]] = op



    def aceitarFilaRecebeminto(self, nome_op):
            if nome_op in self.recebidos:
                op = self.recebidos.pop(nome_op)
                msg = json.dumps({"type": "RES", "opp": self.my_name, "res":"ACE"})
                self.rede.udp_especifico(msg, op["ip"], op["porta"])
                print(f"[DEBUG] Aceite de batalha enviado para {op}")
                self._iniciar_batalha(op, True)


    def negarFilaRecebeminto(self, nome_op):
            if nome_op in self.recebidos:
                op = self.recebidos.pop(nome_op)
                msg = json.dumps({"type": "RES", "opp": self.my_name, "res":"NEG"})
                self.rede.udp_especifico(msg, op["ip"], op["porta"])
                print(f"[DEBUG] Aceite de batalha enviado para {op}")
                self._iniciar_batalha(op, True)




#main
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python client.py <meu_nome> <minha_porta_p2p>")
        sys.exit(1)

    my_name = sys.argv[1]
    my_p2p_port = int(sys.argv[2])

    gerenciador = GerenciadorFilas()
    servidor = Servidor()
    rede = Rede()



    threading.Thread(target=rede.udp_listener, daemon=True).start()

    server_sock = servidor.registrar(my_name, my_p2p_port, crypto.pk_base64())

    while True:
            cmd = input("Digite comando (list, desafiar <nome>, aleatorio, sair): ").strip()
            if cmd == "list":
                servidor.enviar_json(server_sock, {"cmd": "LIST"})
                print("Jogadores online:", servidor.receber_json(server_sock))
            
          #ISSO AQUI VAI TER QUE SER ALTERADO  
            #Falta por fila de desafios e aceites, para dar para desafiar várias pessoas ao mesmo tempo e se uma aceitar, cancela os pendentes
            #E fila de aceite para quem recebeu o desafio escolher quem ele quer desafiar

            
            elif cmd.startswith("desafiar "):
                alvo = cmd.split(" ", 1)[1]
                if alvo == my_name:
                    print("Você não pode se desafiar.")
                    continue
                op = servidor.partida(server_sock, alvo)
                GerenciadorFilas.adicionar_envio(op)

            
            
            elif cmd == "aleatorio":
                op = servidor.partida(server_sock)

          
            #ISSO TA ERRADO, coloquei só para testar
            elif cmd.startswith("aceitar "):
                alvo = cmd.split(" ", 1)[1]
                GerenciadorFilas.aceitarFilaRecebeminto(alvo)
            
            
            elif cmd == "sair":
                print("Saindo...")
                break
            else:
                print("Comando inválido.")

    server_sock.close()
    print("Conexão encerrada.")





    #Falta implementar sistema de matchmaking automático no server (No aleatorio)

    #Falta implesmentar sistema de fila de acietar ou recusar desafios

    #Falta por módulo de "Contatos", ou seja, lista pessoas que você salvou a chave pública para que não precise do servidor para iniciar batalha

    #Falta colocar um módulo de gerenciar escolha do pokemon

    #Falta chat

    #Ranking?

    #Falta interface gráfica

    #Falta colocar mais pokemon na base de dados

    #Falta colocar um hash cumulativo para o servidor validar se é uma vitória válida ou não. Ou mandar cada cliente assinar o movimento que fez com a chave privada e o servidor validar com a pública quando receber os logs