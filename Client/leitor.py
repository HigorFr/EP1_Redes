import threading, sys 


class Leitor(threading.Thread):
    def __init__(self, input_queue):
        super().__init__(daemon=True)
        self.input_queue = input_queue

    def run(self):
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                # remove \n mas preserva string vazia caso usuário só pressione Enter
                self.input_queue.put(line.rstrip("\n"))
            except Exception:
                break
