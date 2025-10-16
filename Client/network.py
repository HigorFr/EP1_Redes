import socket, threading, json, logging


class Network:
    def __init__(self, udp_broadcast_port):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_broadcast_port = udp_broadcast_port
        self.BUFFER_SIZE = 4096

    def start_udp_listener(self, handler):

        def _listen():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind(("0.0.0.0", self.udp_broadcast_port))
            logging.info(f"UDP listener rodando na porta {self.udp_broadcast_port}")

        
            while True:
                try:
                    data, addr = s.recvfrom(self.BUFFER_SIZE)
                    try:
                        msg = json.loads(data.decode())
                        handler(msg, addr)
                    except json.JSONDecodeError:
                        logging.debug("Recebeu UDP inválido")
                except Exception as e:
                    logging.exception("Erro no UDP listener: %s", e)
                    break
        t = threading.Thread(target=_listen, daemon=True)
        t.start()



    def udp_send(self, obj, ip='255.255.255.255', port=None):
        if port is None:
            port = self.udp_broadcast_port
        data = json.dumps(obj).encode()
        self.udp_sock.sendto(data, (ip, port))

    def p2p_listen(self, port, backlog=1, timeout=None):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(backlog)
        if timeout is not None:
            listener.settimeout(timeout)
        conn, addr = listener.accept()
        logging.info(f"P2P: conexão aceita {addr}")
        try:
            listener.close()
        except Exception:
            pass
        return conn

    def p2p_connect(self, ip, port, timeout=5.0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        logging.info(f"P2P: conectado a {(ip, port)}")
        s.settimeout(None)
        return s

    @staticmethod
    def send_line(sock, data):
        sock.sendall(data + b"\n")

    @staticmethod
    def recv_line(fileobj):
        line = fileobj.readline()
        if not line:
            return None
        return line.strip()


# Em client.py, SUBSTITUA a sua classe ServerClient inteira por esta versão
