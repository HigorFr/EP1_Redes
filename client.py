import socket
import threading
import json
import sys
import base64
import os
import queue
import time
import logging
import csv
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

BUFFER_SIZE = 4096


def input_default(prompt, default):
    s = input(f"{prompt}").strip()
    return s if s else default


#Adicionar aqui classe qeu vai gerenciar a base de pokemons e seus ataques
class Pokemon:
    """Guarda os atributos de um único Pokémon."""
    def __init__(self, name, hp, attack, defense, speed, type1, type2):
        self.name = name
        self.hp = int(hp)
        self.attack = int(attack)
        self.defense = int(defense)
        self.speed = int(speed)
        self.type1 = type1
        self.type2 = type2
        # Por enquanto, vamos assumir que todos podem usar os mesmos movimentos
        self.moves = list(MOVES.keys())

    def __repr__(self):
        return f"<Pokemon: {self.name}, HP: {self.hp}>"

class PokemonDB:
    """Carrega e gerencia a base de dados de Pokémon a partir de um arquivo CSV."""
    def __init__(self, filename='pokemon.csv'):
        self.filename = filename
        self.pokemons = {} # Dicionário para guardar os pokémons por nome

    def load(self):
        """Lê o arquivo CSV e popula o dicionário de Pokémons."""
        try:
            with open(self.filename, mode='r', encoding='utf-8-sig') as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    ### MUDANÇA DEFINITIVA: Limpa as chaves (minúsculas E sem espaços) ###
                    row_clean = {key.lower().replace(' ', ''): value for key, value in row.items()}

                    # Agora, usamos o dicionário com as chaves limpas
                    p = Pokemon(
                        name=row_clean['name'],
                        hp=row_clean['hp'],
                        attack=row_clean['attack'],
                        defense=row_clean['defense'],
                        speed=row_clean['speed'],
                        type1=row_clean['type1'],
                        type2=row_clean['type2']
                    )
                    self.pokemons[p.name.lower()] = p
            logging.info(f"{len(self.pokemons)} Pokémon carregados da base de dados.")
        except FileNotFoundError:
            logging.error(f"Erro: Arquivo da base de dados '{self.filename}' não encontrado.")
            raise SystemExit(1)
        except KeyError as e:
            logging.error(f"Erro ao carregar base de dados: a coluna {e} não foi encontrada no arquivo pokemon.csv.")
            logging.error("Verifique se todos os cabeçalhos (Name, HP, Attack, Defense, Speed, Type 1, Type 2) existem no seu CSV.")
            raise SystemExit(1)
        except Exception as e:
            logging.error(f"Erro ao carregar a base de dados de Pokémon: {e}")
            raise SystemExit(1)

    def get_pokemon(self, name):
        """Busca um Pokémon pelo nome (insensível a maiúsculas/minúsculas)."""
        return self.pokemons.get(name.lower())

    def get_all_names(self):
        """Retorna uma lista com os nomes de todos os Pokémon disponíveis."""
        return [p.name for p in self.pokemons.values()]


# Em client.py, SUBSTITUA a função choose_pokemon

def choose_pokemon(pokedex: PokemonDB, input_queue: queue.Queue):
    """Mostra a lista de Pokémon e gerencia a escolha do jogador a partir da fila de entrada."""
    print("\n--- Escolha seu Pokémon para a batalha! ---")
    available_pokemons = pokedex.get_all_names()
    
    for i, name in enumerate(available_pokemons, 1):
        print(f"  {i}. {name}")
    print("Digite o número do Pokémon escolhido: ", end="", flush=True)

    while True:
        try:
            # ### MUDANÇA: Pega a entrada da FILA, não mais do input() ###
            # Espera até 60 segundos pela escolha do jogador.
            choice = input_queue.get(timeout=60)
            
            if not choice: continue
            
            choice_idx = int(choice) - 1
            
            if 0 <= choice_idx < len(available_pokemons):
                chosen_name = available_pokemons[choice_idx]
                chosen_pokemon = pokedex.get_pokemon(chosen_name)
                print(f"Você escolheu {chosen_pokemon.name}!")
                return chosen_pokemon
            else:
                print("Número inválido. Tente novamente: ", end="", flush=True)
        except queue.Empty:
            print("\nTempo para escolha esgotado.")
            return None # Retorna None se o jogador não escolher a tempo
        except (ValueError, IndexError):
            print("\nEntrada inválida. Por favor, digite um número da lista: ", end="", flush=True)


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


# Em client.py, SUBSTITUA a sua classe ServerClient inteira por esta versão

class ServerClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip 
        self.server_port = server_port

    ### MUDANÇA CRÍTICA: send_json agora detecta erros e retorna True/False ###
    @staticmethod
    def send_json(sock, obj):
        """Envia um objeto JSON e retorna True em caso de sucesso, False se a conexão falhar."""
        try:
            line = (json.dumps(obj) + "\n").encode()
            sock.sendall(line)
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            return False

    ### MUDANÇA CRÍTICA: recv_json agora lida com erros de forma mais robusta ###
    @staticmethod
    def recv_json(sock):
        """Recebe um objeto JSON e retorna None se a conexão falhar."""
        buf = b""
        while True:
            try:
                ch = sock.recv(1)
                if not ch: return None # Conexão fechada pelo servidor
                if ch == b"\n": break
                buf += ch
            except (ConnectionAbortedError, ConnectionResetError, OSError):
                return None
        try:
            return json.loads(buf.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def register(self, name, p2p_port, pk_b64, udp_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_ip, self.server_port))
        except (ConnectionRefusedError, socket.gaierror) as e:
            logging.error(f"Não foi possível conectar ao servidor: {e}")
            return None

        if not self.send_json(s, {
            "cmd": "REGISTER", "name": name, "p2p_port": p2p_port,
            "udp_port": udp_port, "public_key": pk_b64
        }):
            logging.error("Falha ao enviar registro para o servidor.")
            return None

        resp = self.recv_json(s)
        if not resp or resp.get("type") != "OK":
            logging.error("Falha ao registrar no servidor: %s", resp)
            s.close()
            return None
            
        logging.info("Registrado no servidor com sucesso")
        return s

    def match(self, sock, target=None):
        cmd = "CHALLENGE" if target else "MATCH_RANDOM"
        if not self.send_json(sock, {"cmd": cmd, "target": target}):
            return None

        resp = self.recv_json(sock)
        if not resp:
            return None
        if resp.get("type") == "MATCH":
            return resp["opponent"]
        if resp.get("type") == "ERR":
            logging.error("Erro do servidor: %s", resp.get("msg"))
            return None
        return None
    
# Em client.py, SUBSTITUA a classe Battle inteira

class Battle:
    class State:
        ### MUDANÇA: O construtor agora também armazena os nomes dos jogadores ###
        def __init__(self, my_player_name: str, opp_player_name: str, my_pokemon: Pokemon, opp_pokemon: Pokemon, my_turn: bool):
            self.my_player_name = my_player_name
            self.opp_player_name = opp_player_name
            self.me_pokemon_name = my_pokemon.name
            self.opp_pokemon_name = opp_pokemon.name
            self.my_pokemon = my_pokemon
            self.opp_pokemon = opp_pokemon
            self.my_hp = my_pokemon.hp
            self.opp_hp = opp_pokemon.hp
            self.my_turn = my_turn
            self.lock = threading.Lock()

        def apply_move(self, move, by_me):
            dmg = MOVES.get(move, 10)
            with self.lock:
                if by_me: self.opp_hp = max(0, self.opp_hp - dmg)
                else: self.my_hp = max(0, self.my_hp - dmg)

        def finished(self):
            return self.my_hp <= 0 or self.opp_hp <= 0

        def winner(self):
            if self.my_hp <= 0 and self.opp_hp <= 0: return "draw"
            # Retorna o NOME DO JOGADOR, não do Pokémon
            if self.my_hp <= 0: return self.opp_player_name
            if self.opp_hp <= 0: return self.my_player_name
            return None

    ### MUDANÇA: O construtor agora aceita os nomes dos jogadores ###
    def __init__(self, my_player_name: str, opp_player_name: str, my_pokemon: Pokemon, p2p_port, opp_info, dial, network, crypto, server_sock, input_queue, pokedex):
        self.my_player_name = my_player_name
        self.opp_player_name = opp_player_name
        self.my_pokemon = my_pokemon
        self.p2p_port = p2p_port
        self.opp_info = opp_info
        self.dial = dial
        self.network = network
        self.crypto = crypto
        self.server_sock = server_sock
        self.shared_key = None
        self.conn = None
        self.fileobj = None
        self.input_queue = input_queue
        self.pokedex = pokedex
        self.state = None

    def prepare(self):
        if self.dial:
            self.conn = self.network.p2p_connect(self.opp_info['ip'], int(self.opp_info['p2p_port']))
        else:
            self.conn = self.network.p2p_listen(self.p2p_port, backlog=1, timeout=10)
        if not self.conn: return False

        self.fileobj = self.conn.makefile("rwb")
        self.shared_key = self.crypto.shared_key(self.opp_info['public_key'])
        
        my_choice_msg = Crypto.encrypt_json(self.shared_key, {"type": "POKEMON_CHOICE", "name": self.my_pokemon.name})
        Network.send_line(self.conn, my_choice_msg.encode())

        self.conn.settimeout(10.0)
        opp_choice_line = Network.recv_line(self.fileobj)
        if not opp_choice_line:
            logging.error("Conexão P2P perdida ao receber escolha do oponente.")
            return False
        
        opp_choice_msg = Crypto.decrypt_json(self.shared_key, opp_choice_line.decode())
        if not opp_choice_msg or opp_choice_msg.get("type") != "POKEMON_CHOICE":
            logging.error("Falha ao receber a escolha de Pokémon do oponente."); return False

        opp_pokemon_name = opp_choice_msg.get("name")
        opp_pokemon = self.pokedex.get_pokemon(opp_pokemon_name)
        if not opp_pokemon:
            logging.error(f"Oponente escolheu um Pokémon inválido: {opp_pokemon_name}"); return False
            
        self.state = Battle.State(
            my_player_name=self.my_player_name, opp_player_name=self.opp_player_name,
            my_pokemon=self.my_pokemon, opp_pokemon=opp_pokemon, my_turn=self.dial
        )
        logging.debug("Shared key e troca de Pokémon feitos com sucesso")
        return True

    def send_encrypted(self, obj):
        assert self.shared_key is not None
        msg = Crypto.encrypt_json(self.shared_key, obj).encode()
        Network.send_line(self.conn, msg)

    def recv_encrypted(self):
        assert self.shared_key is not None
        line = Network.recv_line(self.fileobj)
        if line is None: return None
        return Crypto.decrypt_json(self.shared_key, line.decode())

    def loop(self):
        if not self.state:
            logging.error("Estado da batalha não foi inicializado."); return

        logging.info(f"=== BATALHA: {self.state.my_pokemon.name} vs {self.state.opp_pokemon.name} ===")
        logging.info("Movimentos disponíveis: %s", ", ".join(self.my_pokemon.moves))
        drenar_fila(self.input_queue)
        try:
            while not self.state.finished():
                if self.state.my_turn:
                    print("Seu turno! Seus movimentos:", ", ".join(self.my_pokemon.moves))
                    raw = self.input_queue.get(timeout=60)
                    move = raw.strip()
                    if move not in self.my_pokemon.moves:
                        logging.info("Movimento inválido"); continue
                    self.send_encrypted({"type": "MOVE", "name": move})
                    self.state.apply_move(move, True)
                    logging.info(f"Você usou {move}. HP oponente: {self.state.opp_hp}")
                    self.state.my_turn = False
                else:
                    self.conn.settimeout(70.0)
                    logging.info("Aguardando movimento do oponente...")
                    msg = self.recv_encrypted()
                    if msg is None:
                        logging.warning("Conexão P2P encerrada pelo oponente."); break
                    if msg.get('type') == 'MOVE':
                        mv = msg.get('name')
                        self.state.apply_move(mv, False)
                        logging.info(f"Oponente usou {mv}. Seu HP: {self.state.my_hp}")
                        self.state.my_turn = True
        except queue.Empty:
            print("Tempo de turno esgotado, saindo da batalha...")
        except Exception as e:
            logging.exception("Erro durante a batalha: %s", e)
        finally:
            try: self.conn.close()
            except: pass

        winner = self.state.winner()
        logging.info(f"Resultado da batalha: {winner}")
        
        ### MUDANÇA CRÍTICA: Apenas o vencedor envia o resultado ###
        if winner == self.state.my_player_name:
            logging.info("Eu sou o vencedor. Reportando o resultado ao servidor.")
            ServerClient.send_json(self.server_sock, {
                "cmd": "RESULT", 
                "me": self.state.my_player_name, 
                "opponent": self.state.opp_player_name, 
                "winner": winner
            })
            ServerClient.recv_json(self.server_sock) # Espera a confirmação do servidor
        else:
            logging.info("Eu não sou o vencedor. Não irei reportar o resultado.")


# Em client.py, SUBSTITUA a classe QueueManager

class QueueManager:
    def __init__(self, my_name, p2p_port, network, crypto, server_sock, udp_port, input_queue, pokedex):
        self.my_name = my_name
        self.p2p_port = p2p_port
        self.network = network
        self.crypto = crypto
        self.server_sock = server_sock
        self.udp_port = udp_port
        self.enviados = {}
        self.recebidos = {}
        self.battle_started = threading.Event()
        self.input_queue = input_queue
        self.pokedex = pokedex

    def get_battle_started(self):
        return self.battle_started.is_set()

    def add_send(self, opp, my_pokemon):
        desafio_id = f"{self.my_name}-{opp['name']}"
        q = queue.Queue()
        self.enviados[desafio_id] = q
        t = threading.Thread(target=self._process_send, args=(opp, q, my_pokemon), daemon=True)
        t.start()

    def _process_send(self, opp, q, my_pokemon):
        if self.battle_started.is_set(): return
        op_name = opp['name']
        dest_udp_port = opp.get('udp_port', self.udp_port)
        msg = { "type": "DES", "opponent": { "name": self.my_name, "ip": None, "udp_port": self.udp_port, "p2p_port": self.p2p_port, "public_key": self.crypto.public_key_b64() } }
        try:
            self.network.udp_send(msg, ip=opp.get('ip', '255.255.255.255'), port=dest_udp_port)
            logging.info("Desafio enviado para %s", op_name)
        except Exception as e:
            logging.error("Falha ao enviar desafio: %s", e)
            return
        try:
            resposta = q.get(timeout=20)
        except queue.Empty:
            logging.info("Timeout aguardando resposta de %s", op_name); return
        if self.battle_started.is_set(): return
            
        if resposta and resposta.get('res') == 'ACE':
            logging.info("%s aceitou. Iniciando batalha (sou quem liga).", op_name)
            self.battle_started.set()
            ### MUDANÇA: Passa os nomes dos jogadores para a classe Battle ###
            b = Battle(self.my_name, op_name, my_pokemon, self.p2p_port, opp, dial=True, network=self.network, crypto=self.crypto, server_sock=self.server_sock, input_queue=self.input_queue, pokedex=self.pokedex)
            if b.prepare(): b.loop()
            self.battle_started.clear()
        else:
            logging.info("%s recusou o desafio.", op_name)

    def receive_challenge(self, opp):
        logging.info("Desafio recebido de %s", opp['name'])
        opp["hora"] = time.time()
        self.recebidos[opp['name']] = opp

    def accept(self, opp_name, my_pokemon):
        if opp_name not in self.recebidos:
            logging.info("Nenhum desafio de %s", opp_name); return
        opp = self.recebidos.pop(opp_name)
        if time.time() - opp["hora"] > 20:
            logging.info("Desafio de %s expirou", opp_name); return
            
        res = {"type": "RES", "opp": self.my_name, "res": "ACE"}
        self.network.udp_send(res, ip=opp.get('ip', '255.255.255.255'), port=opp.get('udp_port', self.udp_port))
        logging.info("Aceitei desafio de %s", opp_name)
        self.battle_started.set()
        ### MUDANÇA: Passa os nomes dos jogadores para a classe Battle ###
        b = Battle(self.my_name, opp_name, my_pokemon, self.p2p_port, opp, dial=False, network=self.network, crypto=self.crypto, server_sock=self.server_sock, input_queue=self.input_queue, pokedex=self.pokedex)
        try:
            if b.prepare(): b.loop()
        except Exception as e:
            logging.error("Erro ao preparar batalha: %s", e)
        finally:
            self.battle_started.clear()

    def reject(self, opp_name):
        if opp_name not in self.recebidos:
            logging.info("Nenhum desafio de %s", opp_name); return
        opp = self.recebidos.pop(opp_name)
        res = {"type": "RES", "opp": self.my_name, "res": "NEG"}
        self.network.udp_send(res, ip=opp.get('ip', '255.255.255.255'), port=opp.get('udp_port', self.udp_port))
        logging.info("Recusei desafio de %s", opp_name)

class Leitor(threading.Thread):
    def __init__(self, input_queue):
        super().__init__(daemon=True)
        self.input_queue = input_queue

    def run(self):
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                # remove \n mas preserva string vazia caso usuário só pressione Enter
                self.input_queue.put(line.rstrip("\n"))
            except Exception:
                break

    # util para drenar a fila (descartar tudo que foi lido antes)
def drenar_fila(q):
    try:
        while True:
            q.get_nowait()
    except queue.Empty:
        return

def send_keepalive(sock):
    """
    Roda em uma thread separada para enviar mensagens periódicas ao servidor
    e manter a conexão viva.
    """
    while True:
        try:
            time.sleep(20) # Envia a cada 20 segundos
            if not ServerClient.send_json(sock, {"cmd": "KEEPALIVE"}):
                logging.error("Falha ao enviar keepalive. Conexão perdida.")
                break
        except Exception:
            logging.error("Conexão com o servidor perdida. Encerrando thread de keepalive.")
            break # Encerra a thread se a conexão morrer

def main():
    print("Uso fácil: python client.py <meu_nome> <ip_server> <porta_server> <minha_porta_udp> <minha_porta_p2p>")
    my_name = sys.argv[1] if len(sys.argv) > 1 else input("Seu nome: ").strip()
    server_ip = sys.argv[2] if len(sys.argv) > 2 else input_default("IP do servidor (Vazio para 127.0.0.1)", "127.0.0.1")
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else int(input_default("Porta do servidor (Vazio para 5000)", "5000"))
    udp_port = int(sys.argv[4]) if len(sys.argv) > 4 else int(input_default("Porta UDP (Vazio para 5001)", "5001"))
    p2p_port = int(sys.argv[5]) if len(sys.argv) > 5 else int(input_default("Porta P2P (Vazio para 7000)", "7000"))

    pokedex = PokemonDB()
    pokedex.load()

    input_queue = queue.Queue()
    input_reader = Leitor(input_queue)
    input_reader.start()

    network = Network(udp_broadcast_port=udp_port)
    crypto = Crypto()
    server = ServerClient(server_ip, server_port)

    def udp_handler(msg, addr):
        try:
            t = msg.get('type')
            if t == 'DES':
                opp = msg.get('opponent')
                if opp['name'] == my_name: return # Ignora desafios para si mesmo
                opp['ip'] = addr[0]
                queue_mgr.receive_challenge(opp)
            elif t == 'RES':
                opp_name = msg.get('opp')
                desafio_id = f"{my_name}-{opp_name}"
                q = queue_mgr.enviados.get(desafio_id)
                if q: q.put(msg)
        except Exception:
            logging.exception("Erro tratando mensagem UDP")

    server_sock = server.register(my_name, p2p_port, crypto.public_key_b64(), udp_port)
    queue_mgr = QueueManager(my_name, p2p_port, network, crypto, server_sock, udp_port, input_queue, pokedex)
    network.start_udp_listener(udp_handler)
    threading.Thread(target=send_keepalive, args=(server_sock,), daemon=True).start()

    
    try:
        ### MUDANÇA ###: Loop principal atualizado com 'stats' e 'ranking'
        while True:
            if queue_mgr.get_battle_started():
                time.sleep(0.2); continue
            
            print(f"\nDigite comando (list, stats, ranking, desafiar <nome>, aleatorio, aceitar <nome>, negar <nome>, sair): ", end="", flush=True)

            try:
                raw = input_queue.get()
            except (queue.Empty, KeyboardInterrupt):
                continue

            if queue_mgr.get_battle_started():
                drenar_fila(input_queue); continue

            cmd = raw.strip()
            if not cmd: continue

            parts = cmd.split()
            command = parts[0].lower()
            args = parts[1:]

            if command == 'list':
                ServerClient.send_json(server_sock, {"cmd": "LIST"})
                resp = ServerClient.recv_json(server_sock)
                if resp: print("\nJogadores online:", resp.get("players", []))

            elif command == 'stats':
                ServerClient.send_json(server_sock, {"cmd": "GET_STATS"})
                resp = ServerClient.recv_json(server_sock)
                if resp and resp.get("type") == "STATS":
                    print(f"\n--- Suas Estatísticas ---")
                    print(f"  Vitórias: {resp.get('wins', 0)}")
                    print(f"  Derrotas: {resp.get('losses', 0)}")
                    print(f"-------------------------")
                else: print("Erro ao obter estatísticas:", resp)

            elif command == 'ranking':
                ServerClient.send_json(server_sock, {"cmd": "RANKING"})
                resp = ServerClient.recv_json(server_sock)
                if resp and resp.get("type") == "RANKING":
                    print("\n--- Ranking de Jogadores (por Vitórias) ---")
                    for i, player in enumerate(resp.get("ranking", []), 1):
                        print(f"  {i}. {player['name']} - Vitórias: {player['wins']}, Derrotas: {player['losses']}")
                    print(f"-------------------------------------------")
                else: print("Erro ao obter ranking:", resp)

            elif command in ['desafiar', 'aleatorio', 'aceitar']:
                opp_info = None
                if command in ['desafiar', 'aceitar']:
                    if not args: logging.warning(f"Uso: {command} <nome>"); continue
                    target = args[0]
                    if target == my_name: logging.warning("Você não pode se desafiar."); continue
                    opp_info = server.match(server_sock, target=target)
                elif command == 'aleatorio':
                    opp_info = server.match(server_sock)
                
                if opp_info:
                    my_pokemon = choose_pokemon(pokedex, input_queue)
                    if not my_pokemon: continue
                    if command == 'aceitar':
                        queue_mgr.accept(opp_info['name'], my_pokemon)
                    else:
                        queue_mgr.add_send(opp_info, my_pokemon)
                else:
                    logging.warning("Não foi possível encontrar um oponente.")

            elif command == 'negar':
                if not args: logging.warning("Uso: negar <nome>"); continue
                queue_mgr.reject(args[0])
            
            elif command == 'sair':
                logging.info("Saindo..."); break
            else:
                logging.info("Comando inválido")
                
    finally:
        try: server_sock.close()
        except: pass

if __name__ == '__main__':
    main()
    


    #Falta por módulo de "Contatos", ou seja, lista pessoas que você salvou a chave pública, porta e UDP para que não precise do servidor para iniciar batalha
        #Provavlemente vale a pena deixar um arquivo txt para um usuário sempre iniciar com aquelas configurações, e nese também vai guardar os contatos

    #Falta colocar um módulo de gerenciar escolha do pokemon e colocar mais pokemon na base de dados

    #Falta chat

    #Falta interface gráfica

    #Falta colocar um hash cumulativo para o servidor validar se é uma vitória válida ou não.