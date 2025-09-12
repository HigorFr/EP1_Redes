
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
import traceback

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
                    print(f"[BCAST] {msg}")
            except Exception:
                pass




def send_json(sock, obj):
    line = (json.dumps(obj) + "\n").encode()
    sock.sendall(line)


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


def register_with_server(name, p2p_port, pk_b64):

    #Manda chave pública para o servidor:
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, SERVER_PORT))

    send_json(s, {"cmd":"REGISTER", "name": name, "p2p_port": p2p_port, "public_key": pk_b64})
    resp = recv_json_line(s)
    if not resp or resp.get("type") != "OK":
        print("Falha ao registrar:", resp)
        sys.exit(1)
    return s


def request_match(sock, target=None):
    if target:
        send_json(sock, {"cmd":"CHALLENGE","target": target})
    else:
        send_json(sock, {"cmd":"MATCH_RANDOM"})


    while True:
        resp = recv_json_line(sock)
        if not resp:
            return None
        if resp.get("type") == "MATCH":
            return resp["opponent"]
        elif resp.get("type") == "ERR":
            print("Erro:", resp)
            return None
        else:
            pass





def p2p_listener(port, battle: BattleState):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    listener.bind(("0.0.0.0", port))
    listener.listen(1)
    conn, addr = listener.accept()
    listener.close()
    print(f"[P2P] Conectado com {addr}")
    return conn


def p2p_dial(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print(f"[P2P] Conectado a {(ip, port)}")
    return s







def battle_loop(p2p: socket.socket, battle: BattleState, server_sock: socket.socket, opp_pk , sk):

    #descriptografar a base64 do oponente (que veio do server)

    opp_pk_bytes = base64.b64decode(opp_pk) #voltou para bytes
    opp_pk_obj = x25519.X25519PublicKey.from_public_bytes(opp_pk_bytes) #voltou pra objeto chave
    
    #Estabelece o segredo compartilhado
    shared_key = sk.exchange(opp_pk_obj) 
    aesgcm = AESGCM(shared_key)  #Uso da chave compartilhada para cifrar a comunicação
    
    print(shared_key.hex()) #debug pra ver se ta igual
    
    p2p_file = p2p.makefile("rwb")







    def send_p2p(obj):
 
        nonce = os.urandom(12) #O nonce aqui, sempre 12 (descobri que é convenção)
        line = (json.dumps(obj)).encode()

        print(f"\n Mensagem enviada bruta: {line}")

        # criptografa
        cifrado = aesgcm.encrypt(nonce, line, None)

        # concatena nonce + ciphertext e adiciona \n como bytes


        mensagem = nonce + cifrado #+ b"\n"  

        #Precisa deixar em base64 pois um \n aleatorio pode aparecer na codificação dos bytes

        p2p_file.write(mensagem)
        p2p_file.flush()

        
        print(f"\n Mensagem enviada (base64) criptografada: {mensagem}" )

    def recive_p2p():


        #Problema aqui:
        line = p2p_file.read()

        if not line:
            print("Erro line")
            return None
        
        print(f"\n Mensagem recebida (base64) criptografada: {line}")

        nonce = line[:12]
        if not nonce:
            print("Erro nonce")
            return None
        
        dado = line[12:]
        if not dado:
            print("Erro dado")
            return None
        try:
            decifrado = aesgcm.decrypt(nonce, dado, None)

            print(f"\n Mensagem recebida bruta: {decifrado}")

            return json.loads(decifrado.decode())
        
        except Exception:
            print("Erro decrypt")
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
            msg = recive_p2p()

            if not msg:
                print("Conexão P2P encerrada.")
                continue
            

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






if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python client.py <meu_nome> <minha_porta_p2p>")
        sys.exit(1)

    my_name = sys.argv[1]
    my_p2p_port = int(sys.argv[2])

    threading.Thread(target=udp_listener, daemon=True).start()

    #Definindo chave pública e privada para o cliente

    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()

    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) #Mando para bytes
    pk_b64 = base64.b64encode(pk_bytes).decode()   #dai de bytes para string (pra jogar no json)


    #e aqui envia para o servidor junto com os outros dados
    server_sock = register_with_server(my_name, my_p2p_port, pk_b64)



    #esse é o loop principal. só para com comando 'sair'.
    while True:
        cmd = input("Digite comando (list, desafiar <nome>, aleatorio, sair): ").strip()
        
        op = None #Reinicia a variável de oponente a cada iteração do loop

        if cmd == "list":
            send_json(server_sock, {"cmd": "LIST"})
            resp = recv_json_line(server_sock)
            print("Jogadores online:", resp)

        elif cmd.startswith("desafiar "):
            alvo = cmd.split(" ", 1)[1]
            op = request_match(server_sock, alvo)
            # REMOVEMOS O 'BREAK'.

        elif cmd == "aleatorio":
            op = request_match(server_sock, None)
            # REMOVEMOS O 'BREAK'.

        elif cmd == "sair":
            print("Saindo...")
            break #é o único break que deve existir, para encerrar o programa.
        
        else:
            if cmd: # Só mostra a mensagem se o usuário digitou algo
                print("Comando inválido.")


        #LÓGICA DA BATALHA (AGORA DENTRO DO LOOP)
        #Se uma partida foi encontrada ('op' não é None), executa a batalha.
        if op:
            print("Partida encontrada! Preparando para a batalha...")
            opp_name = op["name"]
            opp_ip = op["ip"]
            opp_port = int(op["p2p_port"])
            opp_pk = op["public_key"]

  

            #"gambiarra" para decidir quem vai iniciar o p2p
            dial = my_name < opp_name

            battle = BattleState(my_name, opp_name)
            


            #arrumar isso, quem inciia é quem tem o nome "menor" invés de velocidade do pokemon
            battle.my_turn = dial

            p2p_socket = None
            try:
                if dial:
                    p2p_socket = p2p_dial(opp_ip, opp_port)
                else:
                    p2p_socket = p2p_listener(my_p2p_port, battle)

                battle_loop(p2p_socket, battle, server_sock, opp_pk, sk)



            except Exception as e:
                print(f"Um erro ocorreu durante a preparação da batalha: {e} em {traceback.print_exc()}")
            finally:
                if p2p_socket:
                    try: 
                        p2p_socket.close()
                    except: 
                        print(e)
                        pass
            
            print("\n--- Batalha finalizada. Retornando ao menu principal. ---\n")
            # Ao final, o 'while True' simplesmente continua para a próxima vez,
            # mostrando o prompt de comando novamente.

    # O programa só chega aqui quando o usuário digita 'sair'
    server_sock.close()
    print("Conexão com o servidor encerrada.")


