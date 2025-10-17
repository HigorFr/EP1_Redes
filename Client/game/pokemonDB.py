import logging
import csv
import ast
import random
from game.move import Move
from game.pokemon import Pokemon

class PokemonDB:
    """Carrega e gerencia a base de dados de Pokémon a partir de um arquivo CSV."""
    def __init__(self, path='Client/data/'):
        self.path = path
        self.pokemons = {} # Dicionário para guardar os pokémons por nome
        self.moves = {}

    def load(self):
        """Lê o arquivo CSV e popula o dicionário de Pokémons."""
        try:


            with open(self.path+"move-data.csv", newline='', encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Normaliza as chaves (caso tenha espaço ou variação)
                    row_clean = {key.lower().replace(' ', ''): value for key, value in row.items()}


                    if(row_clean['category'].lower() == "status"): continue

                    move = Move(
                        name=row_clean['name'].lower(),
                        move_type=row_clean['type'],
                        category=row_clean['category'],
                        contest=row_clean['contest'],
                        pp=row_clean['pp'],
                        power=row_clean['power'],
                        accuracy=row_clean['accuracy'],
                        generation=row_clean['generation']
                    )

                    self.moves[move.name.lower()] = move


            with open(self.path+"pokemon-data.csv", mode='r', encoding='utf-8-sig') as infile:
                reader = csv.DictReader(infile, delimiter=';')
                for row in reader:
                    ### MUDANÇA DEFINITIVA: Limpa as chaves (minúsculas E sem espaços) ###
                    
                    row_clean = {key.lower().replace(' ', ''): value for key, value in row.items() if key is not None}


                    types = ast.literal_eval(row_clean.get('types', '[]'))
                    moves_list = ast.literal_eval(row_clean.get('moves', '[]'))

   
                    type1 = types[0]
                    type2 = types[1] if len(types) > 1 else None


                    valid_moves = [m for m in moves_list if m.lower() in self.moves]
                    unique_valid_moves = list(set(valid_moves))
                    chosen_move_names = random.sample(unique_valid_moves, min(4, len(unique_valid_moves)))
                    objetos_moves = [self.moves[m.lower()] for m in chosen_move_names]


                    p = Pokemon(
                        name=row_clean['name'],
                        hp=row_clean['hp'],
                        attack=row_clean['attack'],
                        defense=row_clean['defense'],
                        special_attack=row_clean['specialattack'],
                        special_defense=row_clean['specialdefense'],
                        speed=row_clean['speed'],
                        type1=type1,
                        type2=type2,
                        moves=objetos_moves
                    )

                    self.pokemons[p.name.lower()] = p

            logging.info(f"{len(self.pokemons)} Pokémon carregados da base de dados.")
       
        except FileNotFoundError:
            logging.error(f"Erro: Arquivo da base de dados '{self.path}' não encontrado.")
            raise SystemExit(1)
        except KeyError as e:
            logging.error(f"Erro ao carregar base de dados: a coluna {e} não foi encontrada no arquivo pokemon.csv.")
            logging.error("Verifique se todos os cabeçalhos (Name, HP, Attack, Defense, Speed, Type 1, Type 2) existem no seu CSV.")
            raise SystemExit(1)
        
        
        #except Exception as e:
        #    logging.error(f"Erro ao carregar a base de dados de Pokémon: {e}")
        #    raise SystemExit(1)

    def get_pokemon(self, name):
        """Busca um Pokémon pelo nome (insensível a maiúsculas/minúsculas)."""
        return self.pokemons.get(name.lower())


    def get_move_by_name(self, move_name):
        return self.moves.get(move_name)


    def get_all_names(self):
        """Retorna uma lista com os nomes de todos os Pokémon disponíveis."""
        return [p.name for p in self.pokemons.values()]

