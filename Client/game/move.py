from utils import Utils


#classe que basicamente contem informações sobre movimento

class Move:
    def __init__(self, name, move_type, category, contest, pp, power, accuracy, generation):
        self.name = name
        self.type = move_type
        self.category = category
        self.contest = contest
        self.pp = Utils.safe_int(pp)
        self.power = Utils.safe_int(power)
        self.accuracy = Utils.safe_int(accuracy) 
        self.generation = Utils.safe_int(generation)

    def getPower(self):
        return self.power
    
    def getName(self):
        return self.name
    
    def getCategory(self):
        return self.category
    

    #isso aqui poderia ter ficado em battle, mas acho que aqui é mais organizado
    def type_multiplier(move_type, defender_types):
        effectiveness = {
            "Normal":    {"Rock": 0.5, "Ghost": 0, "Steel": 0.5},
            "Fire":      {"Fire": 0.5, "Water": 0.5, "Grass": 2, "Ice": 2, "Bug": 2, "Rock": 0.5, "Dragon": 0.5, "Steel": 2},
            "Water":     {"Fire": 2, "Water": 0.5, "Grass": 0.5, "Ground": 2, "Rock": 2, "Dragon": 0.5},
            "Electric":  {"Water": 2, "Electric": 0.5, "Grass": 0.5, "Ground": 0, "Flying": 2, "Dragon": 0.5},
            "Grass":     {"Fire": 0.5, "Water": 2, "Grass": 0.5, "Poison": 0.5, "Ground": 2, "Flying": 0.5, "Bug": 0.5, "Rock": 2, "Dragon": 0.5, "Steel": 0.5},
            "Ice":       {"Fire": 0.5, "Water": 0.5, "Grass": 2, "Ice": 0.5, "Ground": 2, "Flying": 2, "Dragon": 2, "Steel": 0.5},
            "Fighting":  {"Normal": 2, "Ice": 2, "Poison": 0.5, "Flying": 0.5, "Psychic": 0.5, "Bug": 0.5, "Rock": 2, "Ghost": 0, "Dark": 2, "Steel": 2, "Fairy": 0.5},
            "Poison":    {"Grass": 2, "Poison": 0.5, "Ground": 0.5, "Rock": 0.5, "Ghost": 0.5, "Steel": 0, "Fairy": 2},
            "Ground":    {"Fire": 2, "Electric": 2, "Grass": 0.5, "Poison": 2, "Flying": 0, "Bug": 0.5, "Rock": 2, "Steel": 2},
            "Flying":    {"Electric": 0.5, "Grass": 2, "Fighting": 2, "Bug": 2, "Rock": 0.5, "Steel": 0.5},
            "Psychic":   {"Fighting": 2, "Poison": 2, "Psychic": 0.5, "Dark": 0, "Steel": 0.5},
            "Bug":       {"Fire": 0.5, "Grass": 2, "Fighting": 0.5, "Poison": 0.5, "Flying": 0.5, "Psychic": 2, "Ghost": 0.5, "Dark": 2, "Steel": 0.5, "Fairy": 0.5},
            "Rock":      {"Fire": 2, "Ice": 2, "Fighting": 0.5, "Ground": 0.5, "Flying": 2, "Bug": 2, "Steel": 0.5},
            "Ghost":     {"Normal": 0, "Psychic": 2, "Ghost": 2, "Dark": 0.5},
            "Dragon":    {"Dragon": 2, "Steel": 0.5, "Fairy": 0},
            "Dark":      {"Fighting": 0.5, "Psychic": 2, "Ghost": 2, "Dark": 0.5, "Fairy": 0.5},
            "Steel":     {"Fire": 0.5, "Water": 0.5, "Electric": 0.5, "Ice": 2, "Rock": 2, "Fairy": 2, "Steel": 0.5},
            "Fairy":     {"Fire": 0.5, "Fighting": 2, "Poison": 0.5, "Dragon": 2, "Dark": 2, "Steel": 0.5},
        }

        multiplier = 1.0
        for t in defender_types:
            multiplier *= effectiveness.get(move_type, {}).get(t, 1.0)
        return multiplier









