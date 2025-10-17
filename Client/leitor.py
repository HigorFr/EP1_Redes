import threading, sys 
import traceback


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
                self.debug_print_queue()

            except Exception as e:
                print("Erro em Leitor:", e)
                traceback.print_exc()
                break

    def debug_print_queue(self):
        print(list(self.input_queue.queue), self.input_queue.unfinished_tasks)


