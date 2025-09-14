# =============================
# FILE: server.py
# =============================
# Servidor central (TCP) para registro, lista de jogadores e matchmaking.
# Também reenvia eventos via broadcast UDP para espectadores na LAN.

import socket
import threading
import json
import time ### NOVO ###

HOST = "0.0.0.0"
TCP_PORT = 5000
UDP_BROADCAST_PORT = 5001
CLIENT_TIMEOUT = 60 # Em segundos ### NOVO ###

players = {}  # name -> {"addr": (ip, ...), "p2p_port": int, "public_key": str, "last_seen": float, "conn": socket}
lock = threading.Lock()

def udp_broadcast(msg: dict):
    data = json.dumps(msg).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(data, ("255.255.255.255", UDP_BROADCAST_PORT))

### NOVO: Função para verificar clientes inativos ###
def check_inactive_clients():
    """
    Roda em uma thread separada para verificar e remover clientes
    que não enviam mensagens (incluindo keepalives) há muito tempo.
    """
    while True:
        time.sleep(30) # Roda a verificação a cada 30 segundos
        
        # Cria uma cópia para iterar, para não dar problema com a modificação do dicionário
        with lock:
            current_players = list(players.items())
        
        now = time.time()
        
        for name, data in current_players:
            if now - data["last_seen"] > CLIENT_TIMEOUT:
                print(f"[SERVER] Jogador {name} desconectado por inatividade.")
                
                # Pega o lock para remover o jogador
                with lock:
                    # Verifica se o jogador ainda existe antes de tentar removê-lo
                    if name in players:
                        # Fecha a conexão do jogador
                        try:
                            players[name]["conn"].close()
                        except Exception as e:
                            print(f"[SERVER] Erro ao fechar conexão de {name}: {e}")
                        # Remove o jogador da lista
                        del players[name]

                # Notifica a todos que o jogador saiu por timeout
                udp_broadcast({"type":"EVENT", "sub":"LEAVE", "name": name, "reason": "timeout"})


def handle_client(conn: socket.socket, addr):
    name = None
    try:
        conn_file = conn.makefile("rwb")

        def send(obj):
            line = (json.dumps(obj) + "\n").encode()
            conn_file.write(line)
            conn_file.flush()

        while True:
            raw = conn_file.readline()
            if not raw:
                break
            try:
                msg = json.loads(raw.decode().strip())
            except Exception:
                send({"type":"ERR","msg":"invalid_json"})
                continue
            
            ### NOVO: Atualiza o timestamp de 'last_seen' a cada mensagem recebida ###
            if name and name in players:
                with lock:
                    # Verifica se o jogador ainda existe antes de atualizar
                    if name in players:
                        players[name]["last_seen"] = time.time()

            cmd = msg.get("cmd")

            if cmd == "REGISTER":
                name = msg.get("name")
                p2p_port = int(msg.get("p2p_port", 0))
                pk = msg.get("public_key")
                if not name or not p2p_port or not pk:
                    send({"type":"ERR","msg":"missing_fields"})
                    continue
                with lock:
                    if name in players:
                        send({"type":"ERR","msg":"name_in_use"})
                        continue
                    
                    ### NOVO: Adiciona 'last_seen' e o objeto 'conn' ao registrar ###
                    players[name] = {
                        "addr": addr,
                        "public_key": pk,
                        "p2p_port": p2p_port,
                        "last_seen": time.time(),
                        "conn": conn 
                    }
                send({"type":"OK","msg":"registered"})
                udp_broadcast({"type":"EVENT","sub":"JOIN","name":name})
            
            ### NOVO: Comando para responder ao keepalive ###
            elif cmd == "KEEPALIVE":
                # A atualização do 'last_seen' no início do loop já cuida disso.
                # Podemos enviar uma resposta se quisermos, mas não é necessário.
                # send({"type": "OK", "msg": "keepalive_received"})
                pass

            elif cmd == "LIST":
                with lock:
                    lst = [{"name":n, "ip": players[n]["addr"][0], "p2p_port": players[n]["p2p_port"]} for n in players]
                send({"type":"LIST","players": lst})

            elif cmd == "CHALLENGE":
                target = msg.get("target")
                if not target:
                    send({"type":"ERR","msg":"missing_target"})
                    continue
                with lock:
                    if target not in players or name not in players:
                        send({"type":"ERR","msg":"player_not_available"})
                        continue
                    op_ip = players[target]["addr"][0]
                    op_p2p = players[target]["p2p_port"]
                    op_public_key = players[target]["public_key"]
                
                send({"type":"MATCH","opponent": {"name": target, "ip": op_ip, "p2p_port": op_p2p, "public_key": op_public_key}})
                udp_broadcast({"type":"EVENT","sub":"MATCH","p1":name,"p2":target})

            elif cmd == "MATCH_RANDOM":
                with lock:
                    available = [n for n in players if n != name]
                if not available:
                    send({"type":"ERR","msg":"no_opponents"})
                else:
                    import random
                    target = random.choice(available)
                    with lock:
                        if target in players: # Verifica se o alvo ainda está online
                            op_ip = players[target]["addr"][0]
                            op_p2p = players[target]["p2p_port"]
                            op_public_key = players[target]["public_key"]
                            send({"type":"MATCH","opponent": {"name": target, "ip": op_ip, "p2p_port": op_p2p, "public_key": op_public_key}})
                            udp_broadcast({"type":"EVENT","sub":"MATCH","p1":name,"p2":target})
                        else:
                            send({"type":"ERR","msg":"opponent_disconnected"})


            elif cmd == "RESULT":
                me = msg.get("me")
                op = msg.get("opponent")
                winner = msg.get("winner")
                udp_broadcast({"type":"EVENT","sub":"RESULT","p1":me,"p2":op,"winner":winner})
                send({"type":"OK","msg":"result_recorded"})

            else:
                send({"type":"ERR","msg":"unknown_cmd"})

    except Exception as e:
        print(f"[SERVER] Erro na thread do cliente {name or addr}: {e}")

    finally:
        if name:
            print(f"[SERVER] Conexão com {name} encerrada.")
            with lock:
                players.pop(name, None)
            udp_broadcast({"type":"EVENT","sub":"LEAVE","name":name, "reason": "disconnect"})
        try:
            conn.close()
        except Exception:
            pass

def tcp_server():
    ### NOVO: Inicia a thread que verifica inatividade ###
    reaper_thread = threading.Thread(target=check_inactive_clients, daemon=True)
    reaper_thread.start()
    print("[SERVER] Thread de verificação de inatividade iniciada.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, TCP_PORT))
        s.listen()

        print(f"[SERVER] TCP na porta {TCP_PORT}")
        
        while True:
            conn, addr = s.accept()
            print(f"[SERVER] Nova conexão de {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    tcp_server()