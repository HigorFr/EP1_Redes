from utils import Utils


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

    def getDmg(self):
        return self.power
    
    def getName(self):
        return self.name
