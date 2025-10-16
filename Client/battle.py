import logging
import threading, queue

from utils import Utils
from pokemon import Pokemon
from crypto import Crypto
from network import Network
from comunicacaoServer import ServerClient



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
            
            moves = Pokemon.getMoves(); 

            dmg = moves.get(move, 10)

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
        
        
        Utils.drenar_fila(self.input_queue)
        
        
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

