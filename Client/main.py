from crypto import Crypto
from network import Network
from comunicacaoServer import ServerClient
from queueManager import QueueManager
from leitor import Leitor, drenar_fila
from pokemon import PokemonDB, choose_pokemon
import logging
import threading, queue, time, sys


def main():

    #Roda em uma thread separada para enviar mensagens periódicas ao servidor e manter a conexão viva.
    
    def send_keepalive(sock):
        while True:
            try:
                time.sleep(20) # Envia a cada 20 segundos
                if not ServerClient.send_json(sock, {"cmd": "KEEPALIVE"}):
                    logging.error("Falha ao enviar keepalive. Conexão perdida.")
                    break
            except Exception:
                logging.error("Conexão com o servidor perdida. Encerrando thread de keepalive.")
                break # Encerra a thread se a conexão morrer



    def input_default(prompt, default):
        s = input(f"{prompt}").strip()
        return s if s else default


    def udp_handler(msg, addr):
        try:
            t = msg.get('type')
            if t == 'DES':
                opp = msg.get('opponent')
                if opp['name'] == my_name:
                    return  # Ignora desafios para si mesmo
                opp['ip'] = addr[0]
                queue_mgr.receive_challenge(opp)
            elif t == 'RES':
                opp_name = msg.get('opp')
                desafio_id = f"{my_name}-{opp_name}"
                q = queue_mgr.enviados.get(desafio_id)
                if q:
                    q.put(msg)
        except Exception:
            logging.exception("Erro tratando mensagem UDP")



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


    try:
        server_sock = server.register(my_name, p2p_port, crypto.public_key_b64(), udp_port)
    except:
        logging.exception("Tente colocar um servidor válido")
        return

    queue_mgr = QueueManager(my_name, p2p_port, network, crypto, server_sock, udp_port, input_queue, pokedex)
    network.start_udp_listener(udp_handler)
    threading.Thread(target=send_keepalive, args=(server_sock,), daemon=True).start()

    try:
        # Loop principal com comandos atualizados: list, stats, ranking, etc.
        while True:
            if queue_mgr.get_battle_started():
                time.sleep(0.2)
                continue

            print(
                "\nDigite comando (list, stats, ranking, desafiar <nome>, aleatorio, aceitar <nome>, negar <nome>, sair): ",
                end="",
                flush=True
            )

            try:
                raw = input_queue.get()
            except (queue.Empty, KeyboardInterrupt):
                continue

            if queue_mgr.get_battle_started():
                drenar_fila(input_queue)
                continue

            cmd = raw.strip()
            if not cmd:
                continue

            parts = cmd.split()
            command = parts[0].lower()
            args = parts[1:]

            # ======== LIST ========
            if command == 'list':
                if not ServerClient.send_json(server_sock, {"cmd": "LIST"}):
                    logging.error("Falha ao enviar comando LIST para o servidor")
                    continue

                resp = ServerClient.recv_json(server_sock)
                if resp and resp.get("type") == "LIST":
                    players = resp.get("players", [])
                    if players:
                        print("\n--- Jogadores Online ---")
                        for player in players:
                            print(f"  {player}")
                        print("-------------------------")
                    else:
                        print("\nNão há jogadores online no momento.")
                else:
                    logging.error("Resposta inválida do servidor para LIST: %s", resp)

            # ======== STATS ========
            elif command == 'stats':
                ServerClient.send_json(server_sock, {"cmd": "GET_STATS"})
                resp = ServerClient.recv_json(server_sock)
                if resp and resp.get("type") == "STATS":
                    print(f"\n--- Suas Estatísticas ---")
                    print(f"  Vitórias: {resp.get('wins', 0)}")
                    print(f"  Derrotas: {resp.get('losses', 0)}")
                    print(f"-------------------------")
                else:
                    print("Erro ao obter estatísticas:", resp)

            # ======== RANKING ========
            elif command == 'ranking':
                ServerClient.send_json(server_sock, {"cmd": "RANKING"})
                resp = ServerClient.recv_json(server_sock)
                if resp and resp.get("type") == "RANKING":
                    print("\n--- Ranking de Jogadores (por Vitórias) ---")
                    for i, player in enumerate(resp.get("ranking", []), 1):
                        print(f"  {i}. {player['name']} - Vitórias: {player['wins']}, Derrotas: {player['losses']}")
                    print(f"-------------------------------------------")
                else:
                    print("Erro ao obter ranking:", resp)

            # ======== DESAFIAR / ALEATORIO / ACEITAR ========
            elif command in ['desafiar', 'aleatorio', 'aceitar']:
                opp_info = None
                if command in ['desafiar', 'aceitar']:
                    if not args:
                        logging.warning(f"Uso: {command} <nome>")
                        continue
                    target = args[0]
                    if target == my_name:
                        logging.warning("Você não pode se desafiar.")
                        continue
                    opp_info = server.match(server_sock, target=target)
                elif command == 'aleatorio':
                    opp_info = server.match(server_sock)

                if opp_info:
                    my_pokemon = choose_pokemon(pokedex, input_queue)
                    if not my_pokemon:
                        continue
                    if command == 'aceitar':
                        queue_mgr.accept(opp_info['name'], my_pokemon)
                    else:
                        queue_mgr.add_send(opp_info, my_pokemon)
                else:
                    logging.warning("Não foi possível encontrar um oponente.")

            # ======== NEGAR ========
            elif command == 'negar':
                if not args:
                    logging.warning("Uso: negar <nome>")
                    continue
                queue_mgr.reject(args[0])

            # ======== SAIR ========
            elif command == 'sair':
                logging.info("Saindo...")
                break

            # ======== INVÁLIDO ========
            else:
                logging.info("Comando inválido")

    finally:
        try:
            server_sock.close()
        except:
            pass


if __name__ == '__main__':
    main()



    #Falta por módulo de "Contatos", ou seja, lista pessoas que você salvou a chave pública, porta e UDP para que não precise do servidor para iniciar batalha
        #Provavlemente vale a pena deixar um arquivo txt para um usuário sempre iniciar com aquelas configurações, e nese também vai guardar os contatos

    #Falta colocar um módulo de gerenciar escolha do pokemon e colocar mais pokemon na base de dados

    #Falta chat

    #Falta interface gráfica

    #Falta colocar um hash cumulativo para o servidor validar se é uma vitória válida ou n