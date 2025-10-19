import logging
import threading, queue
from utils import Utils
from game.pokemonDB import Pokemon
from rede.crypto import Crypto
from rede.network import Network
from rede.comunicacaoServer import ServerClient
from game.move import Move

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



        @staticmethod
        def calculate_damage(move, attacker, defender):
        
            # Poder base
            power = move.getPower()

            # Escolhe quais atributos usar
            if move.getCategory() == "physical":
                attack = attacker.attack
                defense = defender.defense
            else:
                attack = attacker.special_attack
                defense = defender.special_defense

            # Bônus por tipo (STAB)
            attacker_types = [attacker.type1, attacker.type2]
            stab = 1.5 if move.type in attacker_types else 1.0

            # Eficácia do tipo (simplificada)
            defender_types = [defender.type1, defender.type2]
            type_effectiveness = Move.type_multiplier(move.type,defender_types)

            if(type_effectiveness > 1):
                logging.info("Foi super efetivo!")

            elif(type_effectiveness == 0):
                logging.info("Não teve efeito!")

            elif(type_effectiveness > 0 and type_effectiveness < 1):
                logging.info("Não foi muito efetivo...")


            #Variação aleatória (±15%)
            #random_factor = random.uniform(0.85, 1.0)
                #Retirado pois daria mais trabalho sincronizar


            # Fórmula final simplificada
            damage = (((2 * 50 / 5 + 2) * power * (attack / defense)) / 50 + 2) * stab * type_effectiveness  #* random_factor

            return int(damage)





        def apply_move(self, move, by_me):
            with self.lock:
                if by_me:
                    dmg = self.calculate_damage(move, self.my_pokemon, self.opp_pokemon)
                    self.opp_hp = max(0, self.opp_hp - dmg)
                else:
                    dmg = self.calculate_damage(move, self.opp_pokemon, self.my_pokemon)
                    self.my_hp = max(0, self.my_hp - dmg)



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
        
        logging.debug(f"Shared key e troca de Pokémon feitos com sucesso: { self.shared_key }")

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
            
        
        my_turn = self.my_pokemon.speed > opp_pokemon.speed
        if(self.my_pokemon.speed == opp_pokemon.speed): my_turn = self.dial

        self.state = Battle.State(
            my_player_name=self.my_player_name, opp_player_name=self.opp_player_name,
            my_pokemon=self.my_pokemon, opp_pokemon=opp_pokemon, my_turn=my_turn
        )
        
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
        #logging.info("Movimentos disponíveis: %s", ", ".join(self.my_pokemon.moves_str))
        
        
        #Utils.drenar_fila(self.input_queue)
        
        
        try:
            while not self.state.finished():
                if self.state.my_turn:
                    print("Seu turno! Seus movimentos:", ", ".join([move.capitalize() for move in self.my_pokemon.moves_str])) #Só captalizando pra ficar bonito
                   
                   
                   
                    # Garante que apenas input novo após o prompt será considerado
                    Utils.adicionar_fila(self.input_queue, 'END')
                    
                    Utils.drenar_fila(self.input_queue)
                    raw = self.input_queue.get(timeout=60)
                    move = raw.strip().lower()
                
                    
                    if move not in self.my_pokemon.moves_str:
                        logging.info("Movimento inválido"); continue
                
                
                    self.send_encrypted({"type": "MOVE", "name": move})
                
                    move_obj = self.pokedex.get_move_by_name(move)      
                    self.state.apply_move(move_obj, True)
                
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
                        move_obj = self.pokedex.get_move_by_name(mv)    
                        self.state.apply_move(move_obj, False)
                        
                        logging.info(f"Oponente usou {mv}. Seu HP: {self.state.my_hp}")
                        self.state.my_turn = True




        except queue.Empty:
            logging.info("Tempo de turno esgotado, saindo da batalha...")
        except Exception as e:
            logging.exception("Erro durante a batalha: %s", e)
        finally:
            try: self.conn.close()
            except: pass

        winner = self.state.winner()
        logging.info(f"Resultado da batalha: {winner}")
        
        #Para a main não ficar enchendo o saco com os enters vazios
        Utils.adicionar_fila(self.input_queue, 'END')
        Utils.drenar_fila(self.input_queue)

        ### MUDANÇA CRÍTICA: Apenas o vencedor envia o resultado ###
        if winner == self.state.my_player_name:
            logging.debug("Eu sou o vencedor. Reportando o resultado ao servidor.")
            ServerClient.send_json(self.server_sock, {
                "cmd": "RESULT", 
                "me": self.state.my_player_name, 
                "opponent": self.state.opp_player_name, 
                "winner": winner
            })
            ServerClient.recv_json(self.server_sock) # Espera a confirmação do servidor
        else:
            logging.debug("Eu não sou o vencedor. Não irei reportar o resultado.")

