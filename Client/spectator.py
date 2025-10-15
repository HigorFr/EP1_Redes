# =============================
# FILE: spectator.py
# =============================
# Cliente só para ouvir eventos UDP broadcast do servidor.


import socket
import json

UDP_BROADCAST_PORT = 5001

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", UDP_BROADCAST_PORT))
        print(f"[SPECTATOR] Ouvindo eventos em UDP porta {UDP_BROADCAST_PORT}…")
        while True:
            data, addr = s.recvfrom(4096)
            try:
                msg = json.loads(data.decode())
                if msg.get("type") == "EVENT":
                    print("EVENT:", msg)
            except Exception:
                pass
