from utils import Utils

class Pokemon:   
    """Guarda os atributos de um único Pokémon."""
    def __init__(self, name, hp, attack, defense, speed, type1, type2, moves ):
        self.name = name
        self.hp = Utils.safe_int(hp)
        self.attack = Utils.safe_int(attack)
        self.defense = Utils.safe_int(defense)
        self.speed = Utils.safe_int(speed)
        self.type1 = type1
        self.type2 = type2
        self.moves = moves
        self.moves_str = [move.name for move in moves]


    def __repr__(self):
        return f"<Pokemon: {self.name}, HP: {self.hp}>"

    def getMoves(self):
        return self.moves
