# =============================
# FILE: server.py
# =============================
import socket
import threading
import json
import time

HOST = "0.0.0.0"
TCP_PORT = 5000
UDP_BROADCAST_PORT = 5001
CLIENT_TIMEOUT = 60
STATS_FILE = "player_stats.json" ### MUDANÇA ###

# Dicionário para dados dos jogadores online (em tempo real)
players = {}
lock = threading.Lock()

### MUDANÇA ###
# --- Funções de Persistência de Dados ---
def load_stats():
    """Carrega as estatísticas do arquivo JSON, se ele existir."""
    try:
        with open(STATS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {} # Retorna um dicionário vazio se o arquivo não existir ou for inválido

def save_all_stats():
    """Salva as estatísticas de todos os jogadores (online e offline) em um arquivo JSON."""
    stats_to_save = load_stats() # Carrega o que já existe para não perder dados de jogadores offline
    with lock:
        # Atualiza o dicionário com os dados mais recentes dos jogadores que estão/estavam online
        for name, data in players.items():
            stats_to_save[name] = {
                "wins": data.get("wins", 0),
                "losses": data.get("losses", 0)
            }
    
    with open(STATS_FILE, "w") as f:
        json.dump(stats_to_save, f, indent=4)
    print(f"[STATS] Estatísticas salvas em {STATS_FILE}")

# Carrega as estatísticas salvas ao iniciar o servidor
saved_stats = load_stats()
print(f"[SERVER] Estatísticas de jogadores carregadas: {list(saved_stats.keys())}")


def udp_broadcast(msg: dict):
    data = json.dumps(msg).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(data, ("255.255.255.255", UDP_BROADCAST_PORT))

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
                    data["conn"].close() # Isso vai acionar o 'finally' do handle_client
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
            if not raw:
                break
            try:
                msg = json.loads(raw.decode().strip())
            except Exception:
                send({"type":"ERR","msg":"invalid_json"})
                continue
            
            if name and name in players:
                with lock:
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
                    
                    ### MUDANÇA ###: Carrega stats salvos ou inicializa com 0
                    player_stats = saved_stats.get(name, {"wins": 0, "losses": 0})

                    players[name] = {
                        "addr": addr,
                        "public_key": pk,
                        "p2p_port": p2p_port,
                        "last_seen": time.time(),
                        "conn": conn,
                        "wins": player_stats["wins"],
                        "losses": player_stats["losses"]
                    }
                send({"type":"OK","msg":"registered"})
                udp_broadcast({"type":"EVENT","sub":"JOIN","name":name})
            
            elif cmd == "KEEPALIVE":
                pass

            ### MUDANÇA ###: Novo comando para buscar estatísticas
            elif cmd == "GET_STATS":
                with lock:
                    if name in players:
                        stats = {
                            "type": "STATS",
                            "wins": players[name]["wins"],
                            "losses": players[name]["losses"]
                        }
                        send(stats)
                    else:
                        send({"type": "ERR", "msg": "player_not_found"})

            elif cmd == "LIST":
                with lock:
                    lst = [{"name":n, "ip": players[n]["addr"][0], "p2p_port": players[n]["p2p_port"]} for n in players]
                send({"type":"LIST","players": lst})

            
            elif cmd == "CHALLENGE" or cmd == "MATCH_RANDOM":
                target = msg.get("target")
                with lock:
                    available = [n for n in players if n != name]
                    if cmd == "MATCH_RANDOM":
                        if not available:
                            send({"type":"ERR","msg":"no_opponents"})
                            continue
                        import random
                        target = random.choice(available)

                    if not target or target not in players or name not in players:
                        send({"type":"ERR","msg":"player_not_available"})
                        continue
                    
                    op_ip = players[target]["addr"][0]
                    op_p2p = players[target]["p2p_port"]
                    op_public_key = players[target]["public_key"]
                
                send({"type":"MATCH","opponent": {"name": target, "ip": op_ip, "p2p_port": op_p2p, "public_key": op_public_key}})
                udp_broadcast({"type":"EVENT","sub":"MATCH","p1":name,"p2":target})

            elif cmd == "RESULT":
                me = msg.get("me")
                op = msg.get("opponent")
                winner = msg.get("winner")
                
                #Lógica para atualizar placares
                with lock:
                    if me in players and op in players:
                        if winner == me:
                            players[me]["wins"] += 1
                            players[op]["losses"] += 1
                            print(f"[STATS] Vitória para {me}, derrota para {op}.")
                        elif winner == op:
                            players[op]["wins"] += 1
                            players[me]["losses"] += 1
                            print(f"[STATS] Vitória para {op}, derrota para {me}.")
                
                # Salva os stats após cada partida
                save_all_stats()
                
                udp_broadcast({"type":"EVENT","sub":"RESULT","p1":me,"p2":op,"winner":winner})
                send({"type":"OK","msg":"result_recorded"})

            else:
                send({"type":"ERR","msg":"unknown_cmd"})

    except Exception:
        pass # Erros de conexão são normais quando o cliente fecha

    finally:
        if name:
            print(f"[SERVER] Conexão com {name} encerrada.")
            with lock:
                players.pop(name, None)
            
            save_all_stats() ### MUDANÇA ###: Garante que os stats sejam salvos ao desconectar
            udp_broadcast({"type":"EVENT","sub":"LEAVE","name":name, "reason": "disconnect"})
        try:
            conn.close()
        except Exception:
            pass

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