from utils import Utils

class Pokemon:   
    #Abstração só pra facilitar manipular pokemons
    def __init__(self, name, hp, attack, defense, special_attack, special_defense, speed, type1, type2, moves ):
        self.name = name
        self.hp = Utils.safe_int(hp)
        self.attack = Utils.safe_int(attack)
        self.defense = Utils.safe_int(defense)
        self.special_attack = Utils.safe_int(special_attack)
        self.special_defense = Utils.safe_int(special_defense)
        self.speed = Utils.safe_int(speed)
        self.type1 = type1
        self.type2 = type2
        self.moves = moves
        self.moves_str = [move.name for move in moves]


    def __repr__(self):
        return f"<Pokemon: {self.name}, HP: {self.hp}>"

    def getMoves(self):
        return self.moves
