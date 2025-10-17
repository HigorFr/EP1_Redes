
import logging
import threading
import queue
import time
from game.battle import Battle



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
        
        #APGAR
        logging.warning("Desafio Enviado")
        t.start()

    def _process_send(self, opp, q, my_pokemon):
    
        logging.warning("Desafio RECEB")
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
            resposta = q.get(timeout=50)
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
        b = Battle(self.my_name,     opp_name, my_pokemon, self.p2p_port, opp, dial=False, network=self.network, crypto=self.crypto, server_sock=self.server_sock, input_queue=self.input_queue, pokedex=self.pokedex)
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