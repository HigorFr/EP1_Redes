import queue
class Utils:
    def drenar_fila(q):
        try:
            while True:
                q.get_nowait()
        except queue.Empty:
            return
        

    def safe_int(value, default=0):
        """Tenta converter value para int. Se não conseguir, retorna default."""
        try:
            if value in (None, '', 'None', '???'):
                return default
            return int(value)
        except ValueError:
            return default