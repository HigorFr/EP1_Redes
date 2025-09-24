# =============================
# FILE: server.py
# =============================
# Servidor central (TCP) para registro, lista de jogadores e matchmaking.
# Também reenvia eventos via broadcast UDP para espectadores na LAN.

import socket
import threading
import json

HOST = "0.0.0.0"
TCP_PORT = 5000
UDP_BROADCAST_PORT = 5001

players = {}  # name -> {"addr": (ip, tcp_port_from_socket), "p2p_port": int}
lock = threading.Lock()

def udp_broadcast(msg: dict):
    data = json.dumps(msg).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(data, ("255.255.255.255", UDP_BROADCAST_PORT))




def handle_client(conn: socket.socket, addr):
    name = None
    try:
        conn_file = conn.makefile("rwb")

        def send(obj):
            line = (json.dumps(obj) + "\n").encode()
            conn_file.write(line)
            conn_file.flush()

        # Protocolo simples por linhas em JSON
        # Mensagens esperadas:
        #   {"cmd":"REGISTER","name":"Ash","p2p_port":7000}
        #   {"cmd":"LIST"}
        #   {"cmd":"CHALLENGE","target":"Misty"}
        #   {"cmd":"MATCH_RANDOM"}
        #   {"cmd":"RESULT","me":"Ash","opponent":"Misty","winner":"Ash"}
        
        while True:
            raw = conn_file.readline()
            if not raw:
                break
            try:
                msg = json.loads(raw.decode().strip())
            except Exception:
                send({"type":"ERR","msg":"invalid_json"})
                continue

            cmd = msg.get("cmd")



            if cmd == "REGISTER":
                name = msg.get("name")
                p2p_port = int(msg.get("p2p_port", 0))
                udp_port = int(msg.get("udp_port", 0))

                pk = msg.get("public_key") #<-Pego a chave pública que o cliente me enviou
                if not name or not p2p_port:
                    send({"type":"ERR","msg":"missing_fields"})
                    continue
                with lock:
                    if name in players:
                        send({"type":"ERR","msg":"name_in_use"})
                        continue

                    players[name] = {"addr": addr, "public_key": pk, "p2p_port": p2p_port, "udp_port": udp_port} #<- Salvo as informações


                send({"type":"OK","msg":"registered"})
                
                
                udp_broadcast({"type":"EVENT","sub":"JOIN","name":name})




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
                    op_public_key = players[target]["public_key"] # <- Pego a chave pública do desafiado e envio para o cliente que fez o desafio
                    op_udp_port = players[target]["udp_port"]

                # Notifica ambos com as infos do outro
                send({"type":"MATCH","opponent": {"name": target, "ip": op_ip, "p2p_port": op_p2p, "public_key": op_public_key, "udp_port": op_udp_port}})
                #Tenta notificar o desafiado se ele ainda estiver conectado (melhorias: push async)
                
                
                #Aqui, por simplicidade, apenas broadcasta o match para espectadores
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
                        op_ip = players[target]["addr"][0]
                        op_p2p = players[target]["p2p_port"]
                        op_public_key = players[target]["public_key"]
                        op_udp_port = players[target]["udp_port"]

                        send({"type":"MATCH","opponent": {"name": target, "ip": op_ip, "p2p_port": op_p2p, "public_key": op_public_key, "udp_port": op_udp_port}})


                    
                    udp_broadcast({"type":"EVENT","sub":"MATCH","p1":name,"p2":target})





            elif cmd == "RESULT":
                me = msg.get("me")
                op = msg.get("opponent")
                winner = msg.get("winner")
                udp_broadcast({"type":"EVENT","sub":"RESULT","p1":me,"p2":op,"winner":winner})
                
                send({"type":"OK","msg":"result_recorded"})






            else:
                send({"type":"ERR","msg":"unknown_cmd"})




    except Exception as e:
        # print or log
        pass




    finally:
        if name:
            with lock:
                players.pop(name, None)
            udp_broadcast({"type":"EVENT","sub":"LEAVE","name":name})
        try:
            conn.close()
        except Exception:
            pass


def tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, TCP_PORT))
        s.listen()


        print(f"[SERVER] TCP on {HOST}:{TCP_PORT}")
        
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    tcp_server()
