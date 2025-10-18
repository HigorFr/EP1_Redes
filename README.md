# EP1_Redes

Este repositório contém o EP1 (primeiro exercício prático) da disciplina de Redes de Computadores. O projeto implementa uma aplicação cliente-servidor, demonstrando conceitos fundamentais de redes, como comunicação via sockets, protocolos de transporte e arquitetura cliente-servidor. O relatório do projeto foi confeccionado utilizando TeX.

## Estrutura do Repositório

O repositório está organizado da seguinte forma:

* **Client/**: Contém o executável e recursos relacionados ao cliente da aplicação, como dados dos pokemons.
* **Server/**: Contém o executável e recursos relacionados ao servidor da aplicação, como dados dos jogadores.
* **src/**: Contém os arquivos de código-fonte, seja do servidor ou do cliente. Arquivo principal do cliente em Client/main.py, e do servidor em Server/server.py
* **Readme.txt**: Informações adicionais sobre o projeto. (isto aqui)

## Tecnologias Utilizadas

* **Python**: Linguagem de programação utilizada para implementar a aplicação cliente e servidor.
* **Sockets**: Mecanismo de comunicação dentro do Python utilizado para comunicação entre cliente e servidor.
* **LaTeX**: Utilizado para a confecção do relatório do projeto.

## Como Executar

Você pode executar o projeto das seguintes maneiras:

1. Rodando a main usando a pasta `src/Client` como raiz para o cliente e `src/Server` para o servidor.
2. Utilizando os executáveis já disponíveis no repositório, que realizam toda a configuração automaticamente.

### Passos para utilização:

1. Escolha um nome para entrar no servidor.

2. Insira o IP do servidor e a porta.

3. Escolha uma porta UDP e uma TCP para suas comunicações (lembre-se que se houver mais de um cliente na mesma máquina ou servidor, as portas devem ser diferentes).

4. Escolha um comando:

   * `list`: Lista os usuários conectados.
   * `stats`: Mostra suas estatísticas.
   * `ranking`: Mostra o ranking de todos os jogadores registrados no servidor.
   * `desafiar <nome>`: Desafia outro jogador para batalha.
   * `aleatorio`: Desafia um jogador aleatório.
   * `aceitar <nome>`: Aceita um desafio recebido.
   * `negar <nome>`: Nega um desafio recebido.
   * `sair`: Encerra a conexão com o servidor.

5. Ao desafiar alguém (ex: jogador B), você deverá escolher entre 10 pokémons aleatórios para sua batalha, cada um com 4 movimentos aleatórios da pool dele.

6. Aguarde que o jogador B aceite. Enquanto isso, você pode tentar desafiar outros jogadores até alguém aceitar.

7. Quando a batalha terminar, o vencedor reporta o resultado ao servidor para registrar no ranking.

## Contribuições

Este projeto foi desenvolvido como parte de uma atividade acadêmica. Contribuições são bem-vindas, especialmente para aprimorar a documentação ou adicionar melhorias ao código.
