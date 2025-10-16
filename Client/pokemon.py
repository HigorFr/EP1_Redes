import logging
import csv


class Pokemon:
   
   
    """Guarda os atributos de um único Pokémon."""
    def __init__(self, name, hp, attack, defense, speed, type1, type2):
        self.name = name
        self.hp = int(hp)
        self.attack = int(attack)
        self.defense = int(defense)
        self.speed = int(speed)
        self.type1 = type1
        self.type2 = type2
        # Por enquanto, vamos assumir que todos podem usar os mesmos movimentos

        MOVES = {
                "Tackle": 15,
                "Thunderbolt": 25,
                "QuickAttack": 12,
                "Flamethrower": 25,
                "HK": 100
            }


        self.moves = list(MOVES.keys())

    def __repr__(self):
        return f"<Pokemon: {self.name}, HP: {self.hp}>"

class PokemonDB:
    """Carrega e gerencia a base de dados de Pokémon a partir de um arquivo CSV."""
    def __init__(self, filename='pokemon.csv'):
        self.filename = filename
        self.pokemons = {} # Dicionário para guardar os pokémons por nome

    def load(self):
        """Lê o arquivo CSV e popula o dicionário de Pokémons."""
        try:
            with open(self.filename, mode='r', encoding='utf-8-sig') as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    ### MUDANÇA DEFINITIVA: Limpa as chaves (minúsculas E sem espaços) ###
                    row_clean = {key.lower().replace(' ', ''): value for key, value in row.items()}

                    # Agora, usamos o dicionário com as chaves limpas
                    p = Pokemon(
                        name=row_clean['name'],
                        hp=row_clean['hp'],
                        attack=row_clean['attack'],
                        defense=row_clean['defense'],
                        speed=row_clean['speed'],
                        type1=row_clean['type1'],
                        type2=row_clean['type2']
                    )
                    self.pokemons[p.name.lower()] = p
            logging.info(f"{len(self.pokemons)} Pokémon carregados da base de dados.")
        except FileNotFoundError:
            logging.error(f"Erro: Arquivo da base de dados '{self.filename}' não encontrado.")
            raise SystemExit(1)
        except KeyError as e:
            logging.error(f"Erro ao carregar base de dados: a coluna {e} não foi encontrada no arquivo pokemon.csv.")
            logging.error("Verifique se todos os cabeçalhos (Name, HP, Attack, Defense, Speed, Type 1, Type 2) existem no seu CSV.")
            raise SystemExit(1)
        except Exception as e:
            logging.error(f"Erro ao carregar a base de dados de Pokémon: {e}")
            raise SystemExit(1)

    def get_pokemon(self, name):
        """Busca um Pokémon pelo nome (insensível a maiúsculas/minúsculas)."""
        return self.pokemons.get(name.lower())

    def get_all_names(self):
        """Retorna uma lista com os nomes de todos os Pokémon disponíveis."""
        return [p.name for p in self.pokemons.values()]

