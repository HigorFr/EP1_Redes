# =============================
# FILE: server.py
# =============================
import socket
import threading
import json
import time
import logging


HOST = "0.0.0.0"
TCP_PORT = 5000
UDP_BROADCAST_PORT = 5001
CLIENT_TIMEOUT = 60

import os, sys


logging.basicConfig(level=logging.INFO, format='\n[%(levelname)s] %(message)s')

#Para mudar o para debug só descomentar isso
#logging.basicConfig(level=logging.DEBUG, format='\n[%(levelname)s] %(message)s')



players = {}
lock = threading.Lock()


#resolver problema do executável não achar o json
def get_executable_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

STATS_FILE = os.path.join(get_executable_dir(), "player_stats.json")




# --- Funções de Persistência de Dados ---
def load_stats():
    """Carrega as estatísticas do arquivo JSON, se ele existir."""
    try:
        with open(STATS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}



### MUDANÇA: Função de salvar agora é mais inteligente ###
def save_all_stats():
    with lock:
        # Carrega o que já existe no disco para não perder dados de jogadores offline
        all_stats = load_stats()
        # Atualiza o dicionário com os dados mais recentes dos jogadores que estão/estavam online nesta sessão
        for name, data in players.items():
            all_stats[name] = {
                "wins": data.get("wins", 0),
                "losses": data.get("losses", 0)
            }

    with open(STATS_FILE, "w") as f:
        json.dump(all_stats, f, indent=4)
    print(f"[STATS] Estatísticas salvas em {STATS_FILE}")

# Carrega as estatísticas salvas ao iniciar o servidor
saved_stats = load_stats()
print(f"[SERVER] Estatísticas de jogadores carregadas: {list(saved_stats.keys())}")


def udp_broadcast(msg: dict):
    data = json.dumps(msg).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        with lock:
            for name, data_player in players.items():
                addr = data_player["addr"][0]
                port = data_player["udp_port"]
                try:
                    s.sendto(data, (addr, port))
                    logging.debug(f"[UDP] Enviado para {name} ({addr}:{port})")
                except Exception as e:
                    logging.warning(f"[UDP] Falha ao enviar para {name} ({addr}:{port}) - {e}")




def check_inactive_clients():
    while True:
        time.sleep(30)
        with lock:
            current_players = list(players.items())
        now = time.time()
        for name, data in current_players:
            if now - data.get("last_seen", now) > CLIENT_TIMEOUT:
                print(f"[SERVER] Jogador {name} desconectado por inatividade.")
                try:
                    data["conn"].close()
                except Exception:
                    pass

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
            if not raw: break
            try:
                msg = json.loads(raw.decode().strip())
            except Exception:
                send({"type":"ERR","msg":"invalid_json"}); continue
            
            if name in players:
                with lock:
                    if name in players:
                        players[name]["last_seen"] = time.time()

            cmd = msg.get("cmd")

            logging.debug(f"Mensagem recebedida {msg}")

            if cmd == "REGISTER":
                name = msg.get("name")
                p2p_port = int(msg.get("p2p_port", 0)); udp_port = int(msg.get("udp_port", 0))
                pk = msg.get("public_key")
                
                if not all([name, p2p_port, pk, udp_port]):
                    send({"type":"ERR","msg":"missing_fields"}); continue
              

             # obtém o IP real da máquina do servidor (não o localhost) nos casos de um cliente também ser o servidor
                if addr[0] in ("127.0.0.1", "localhost"):
                    import socket

   
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                            s.connect(("8.8.8.8", 80))  # Conecta temporariamente ao Google DNS só pra descobrir o IP local
                            client_ip = s.getsockname()[0]
           

                    except Exception:
                        client_ip = "127.0.0.1"  # fallback se ele n conseguir pegar o ip

                else: client_ip = addr[0]
        
                with lock:
                    if name in players:
                        send({"type":"ERR","msg":"name_in_use"}); continue
                    player_stats = saved_stats.get(name, {"wins": 0, "losses": 0})
                    players[name] = {
                        "addr": (client_ip, addr[1]), "public_key": pk, "p2p_port": p2p_port,
                        "udp_port": udp_port, "last_seen": time.time(), "conn": conn,
                        "wins": player_stats["wins"], "losses": player_stats["losses"]
                    }


                print(f"[SERVER] Registrado {name} com ip {client_ip} p2p_port {p2p_port}", flush=True)

                send({"type":"OK","msg":"registered"})
                udp_broadcast({"type":"EVENT","sub":"JOIN","name":name})
            





            elif cmd == "KEEPALIVE":
                pass




            elif cmd == "GET_STATS":
                with lock:
                    if name in players:
                        send({"type": "STATS", "wins": players[name]["wins"], "losses": players[name]["losses"]})
                    else: send({"type": "ERR", "msg": "player_not_found"})






            elif cmd == "RANKING":
                with lock:
                    all_stats = load_stats()
                    ranking_list = sorted(all_stats.items(), key=lambda item: item[1].get('wins', 0), reverse=True)
                formatted_ranking = [{"name": n, "wins": s["wins"], "losses": s["losses"]} for n, s in ranking_list]
                send({"type": "RANKING", "ranking": formatted_ranking})
            elif cmd == "LIST":
                with lock:
                    player_list = [
                        {"name": n, "ip": d["addr"][0], "udp_port": d["udp_port"], "p2p_port": d["p2p_port"]}
                        for n, d in players.items()
                    ]
                send({"type": "LIST", "players": player_list})






            elif cmd in ("CHALLENGE", "MATCH_RANDOM", "GET_INFO"):
                target = msg.get("target")
                with lock:
                    if cmd == "MATCH_RANDOM":
                        available = [n for n in players if n != name]
                        if not available: send({"type":"ERR","msg":"no_opponents"}); continue
                        import random
                        target = random.choice(available)
                    if not target or target not in players:
                        send({"type":"ERR","msg":"player_not_available"}); continue
                    
                    player_data = players[target]
                    info = {"type": "MATCH", "opponent": {
                                "name": target, "ip": player_data["addr"][0],
                                "p2p_port": player_data["p2p_port"], "udp_port": player_data["udp_port"],
                                "public_key": player_data["public_key"]}}
                    send(info)
                if cmd == "CHALLENGE":
                    udp_broadcast({"type":"EVENT","sub":"MATCH","p1":name,"p2":target})

            ### MUDANÇA: Lógica de RESULT simplificada e corrigida ###
            elif cmd == "RESULT":
                me = msg.get("me"); op = msg.get("opponent"); winner = msg.get("winner")
                
                with lock:
                    # 1. Carrega o estado atual do placar
                    all_stats = load_stats()

                    # 2. Garante que ambos os jogadores existam no placar
                    p1_stats = all_stats.get(me, {"wins": 0, "losses": 0})
                    p2_stats = all_stats.get(op, {"wins": 0, "losses": 0})

                    # 3. Atualiza os placares
                    if winner == me and me != op: # Impede que empates contem como vitória/derrota
                        p1_stats["wins"] += 1
                        p2_stats["losses"] += 1
                    elif winner == op and me != op:
                        p2_stats["wins"] += 1
                        p1_stats["losses"] += 1
                    
                    # 4. Coloca os placares atualizados de volta no dicionário principal
                    all_stats[me] = p1_stats
                    all_stats[op] = p2_stats

                    # 5. Atualiza os dados dos jogadores que estão online
                    if me in players: players[me].update(p1_stats)
                    if op in players: players[op].update(p2_stats)

                    # 6. Salva o dicionário inteiro de volta no arquivo
                    with open(STATS_FILE, "w") as f:
                        json.dump(all_stats, f, indent=4)
                    print(f"[STATS] Estatísticas de {me} e {op} atualizadas e salvas.")
                
                #udp_broadcast({"type":"EVENT","sub":"RESULT","p1":me,"p2":op,"winner":winner})
                send({"type":"OK","msg":"result_recorded"})
            else:
                send({"type":"ERR","msg":"unknown_cmd"})


    except Exception:
        pass
    finally:
        if name:
            print(f"[SERVER] Conexão com {name} encerrada.")
            save_all_stats()
            with lock:
                players.pop(name, None)
            udp_broadcast({"type":"EVENT","sub":"LEAVE","name":name, "reason": "disconnect"})
        try: conn.close()
        except: pass



def tcp_server():
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
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()





if __name__ == "__main__":
    tcp_server()