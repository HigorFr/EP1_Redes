import queue
class Utils:
    def drenar_fila(q):
        try:
            while True:
                q.get_nowait()
        except queue.Empty:
            return