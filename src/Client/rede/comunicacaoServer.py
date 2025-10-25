import socket
import json
import logging



#Isso aqui é só uma camada a mais de abstração para comunicações diretas com o servidor, tudo bem autoexplicativo

class ServerClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port

    #send_json agora detecta erros e retorna True/False dependendo
    @staticmethod
    def send_json(sock, obj):
        """Envia um objeto JSON e retorna True em caso de sucesso, False se a conexão falhar."""
        try:
            line = (json.dumps(obj) + "\n").encode()
            sock.sendall(line)
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            return False

    
    #recv_json agora lida com erros de forma mais robusta
    @staticmethod
    def recv_json(sock):
        """Recebe um objeto JSON e retorna None se a conexão falhar."""
        buf = b""
        sock.settimeout(5.0)  #adiciona timeout para evitar bloqueio eterno
        try:
            while True:
                ch = sock.recv(1)
                if not ch:
                    return None  #Conexão fechada
                if ch == b"\n":
                    break
                buf += ch
        except (ConnectionAbortedError, ConnectionResetError, OSError, socket.timeout):
            return None
        finally:
            sock.settimeout(None)  #Remove o timeout
        try:
            return json.loads(buf.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None


    def register(self, name, p2p_port, pk_b64, udp_port):
        try:
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.server_ip, self.server_port))

        except (ConnectionRefusedError, socket.gaierror) as e:
            logging.info("Não foi possível conectar ao servidor")
            s.close() 
            raise



        if not self.send_json(s, {
            "cmd": "REGISTER",
            "name": name,
            "p2p_port": p2p_port,
            "udp_port": udp_port,
            "public_key": pk_b64
        }):
            logging.error("Falha ao enviar registro para o servidor.")
            return None

        resp = self.recv_json(s)
        if not resp or resp.get("type") != "OK":
            logging.error("Falha ao registrar no servidor: %s", resp)
            s.close()
            return None

        logging.info("Registrado no servidor com sucesso")
        return s

    #O random, não é nadamais que a mensagem do match sem o argumento de target
    #o servidor fica responsavel de enviar para alguem aleaorio
    def match(self, sock, target=None):
        cmd = "CHALLENGE" if target else "MATCH_RANDOM"
        if not self.send_json(sock, {"cmd": cmd, "target": target}):
            return None

        resp = self.recv_json(sock)
        if not resp:
            return None

        if resp.get("type") == "MATCH":
            return resp["opponent"]

        if resp.get("type") == "ERR":
            logging.error("Erro do servidor: %s", resp.get("msg"))
            return None

        return None
