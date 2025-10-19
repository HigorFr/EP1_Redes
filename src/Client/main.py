from rede.crypto import Crypto
from rede.network import Network
from rede.comunicacaoServer import ServerClient
from rede.queueManager import QueueManager
from leitor import Leitor
from game.pokemonDB import PokemonDB
import logging
import threading, queue, time, sys
from utils import Utils



logging.basicConfig(level=logging.INFO, format='\n[%(levelname)s] %(message)s')

#Para mudar o para debug só descomentar isso
#logging.basicConfig(level=logging.DEBUG, format='\n[%(levelname)s] %(message)s')




import random
import queue


#Isso foi feito na main por motivos de facilidade
def choose_pokemon(pokedex: PokemonDB, input_queue: queue.Queue):
    print("\n--- Escolha dentre esses Pokémon para a batalha! ---")
    all_pokemons = pokedex.get_all_names()

    # Seleciona 10 Pokémon aleatórios (ou menos, se tiver menos de 10 disponíveis)
    available_pokemons = random.sample(all_pokemons, k=min(10, len(all_pokemons)))
    
    for i, name in enumerate(available_pokemons, 1):
        print(f"  {i}. {name}")
    print("Digite o número do Pokémon escolhido: ", end="", flush=True)

    while True:
        try:
            # Espera até 60 segundos pela escolha do jogador
            choice = input_queue.get(timeout=60)
            
            if not choice:
                continue
            
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
            return None
        except (ValueError, IndexError):
            print("\nEntrada inválida. Por favor, digite um número da lista: ", end="", flush=True)
            




#Roda em uma thread separada para enviar mensagens periódicas ao servidor e manter a conexão viva.
def send_keepalive(sock,input_queue, queue):
    while True:
        time.sleep(20) # Envia a cada 20 segundos (Foi usado mais para teste, mas o tempo poderia ser menor)
        if not queue.get_battle_started():    
            try:
                logging.debug("Enviado Keep alive.")
                if not ServerClient.send_json(sock, {"cmd": "KEEPALIVE"}):
                    logging.error("Falha ao enviar keepalive. Conexão perdida. Batalhas em andamento não foram salvas")
                    logging.error("Por favor reabra o programa com um servidor válido.")
                    #Gambiarra totalmente funcional e lógica
                    Utils.adicionar_fila(input_queue, 'Sair')
                    break
            except Exception:
                logging.error("Conexão com o servidor perdida. Por favor reabra o programa com um servidor válido.")
                Utils.adicionar_fila(input_queue, 'Sair')
                break # Encerra a thread se a conexão morrer



def input_default(prompt, default):
    s = input(f"{prompt}").strip()
    return s if s else default



def main():
    
    print("Uso fácil: python client.py <meu_nome> <ip_server> <porta_server> <minha_porta_udp> <minha_porta_tcp>")
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


#Gerenciador do que ele receber de UDP
    def udp_handler(msg, addr):
        try:
            print(msg)
            print("============")
            #apagar
            t = msg.get('type')
            if t == 'DES':
                opp = msg.get('opponent')
                if opp['name'] == my_name:
                    return  # Ignora desafios para si mesmo
                opp['ip'] = addr[0]
                queue_mgr.receive_challenge(opp)

            elif t == 'EVENT':
                sub = msg.get('sub')
                if sub == 'JOIN':
                    joined_name = msg.get('name')
                    logging.info(f"O jogador {joined_name} entrou no servidor.")

                elif sub == 'LEAVE':
                    joined_name = msg.get('name')
                    logging.info(f"O jogador {joined_name} saiu do servidor.")

            elif t == 'RES':
                opp_name = msg.get('opp')
                desafio_id = f"{my_name}-{opp_name}"
                q = queue_mgr.enviados.get(desafio_id)
                if q:
                    q.put(msg)
        except Exception:
            logging.exception("Erro tratando mensagem UDP")


    try:
        server_sock = server.register(my_name, p2p_port, crypto.public_key_b64(), udp_port)
    except Exception:
        logging.info("Erro, tente colocar um servidor válido")
        return

    queue_mgr = QueueManager(my_name, p2p_port, network, crypto, server_sock, udp_port, input_queue, pokedex)
    
    network.start_udp_listener(udp_handler)
    threading.Thread(target=send_keepalive, args=(server_sock, input_queue, queue_mgr), daemon=True).start()

    try:
        # Loop principal com comandos atualizados: list, stats, ranking, etc.
        while True:
            if queue_mgr.get_battle_started():
                time.sleep(0.2)
                continue

            print(
                "\nDigite comando (list, stats, ranking, desafiar <nome>, aleatorio, aceitar <nome>, negar <nome>, sair): ",
                end="",
                flush=False
            )

            try:
                raw = input_queue.get()
            except (queue.Empty, KeyboardInterrupt):
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

    except:
        print("Erro de comunicação com o servidor, encerrando...")

    finally:
        try:
            server_sock.close()
            return
        except:
            return


if __name__ == '__main__':
    main()


    #O que falta (que provavelemtne não vai dar tempo):

    #Falta por módulo de "Contatos", ou seja, lista pessoas que você salvou a chave pública, porta e UDP para que não precise do servidor para iniciar batalha
        #Provavlemente vale a pena deixar um arquivo txt para um usuário sempre iniciar com aquelas configurações, e nese também vai guardar os contatos

    #Falta chat

    #Falta interface gráfica

    #Falta colocar um hash cumulativo para o servidor validar se é uma vitória válida ou n