# Trabalhos_Redes
Repositório para criação de Trabalhos da Disciplina de Redes de Computadores, Departamento da Computação UFSCar 

# Parte I
Camada de Aplicação

*Implementação de Cliente e Servidor através de Sockets usando protocolo TCP na linguagem Python

# Parte II
Camada de Transporte

Implemente o protocolo TCP. Para obter a nota completa, você deve implementar e exercitar (testar e comprovar que funcionam) os seguintes aspectos do protocolo TCP:

    Estabelecer conexão (handshake SYN, SYN+ACK, ACK) com número de sequência inicial aleatório.
    Transmitir e receber corretamente os segmentos.
    Retransmitir corretamente segmentos que forem perdidos ou corrompidos.
    Estimar o timeout para retransmissão de acordo com as recomendações do livro-texto (RFC 2988).
    Implementar a semântica para timeout e ACKs duplos de acordo com as recomendações do livro-texto.
    Tratar e informar corretamente o campo window size, implementando controle de fluxo.
    Realizar controle de congestionamento de acordo com as recomendações do livro-texto (RFC 5681).
    Fechar a conexão de forma limpa (lidando corretamente com a flag FIN).

Se você tiver adotado uma plataforma com suporte nativo a sockets, provavelmente você conseguirá utilizar algum tipo de raw socket que exponha ao espaço de usuário o pacote processado somente até a camada de rede. Este exemplo mostra como isso pode ser feito no Linux em linguagem Python.

Nesse caso, a dica é fazer testes plugando a sua implementação de TCP a uma implementação muito simples de servidor HTTP (por exemplo, que ignore a requisição e volte sempre a mesma resposta, em uma conexão não-persistente) e utilizar um cliente pronto (por exemplo o wget) para conectar-se a ele. Volte uma resposta HTTP bastante grande, assim você pode:

    Testar o controle de fluxo teclando Ctrl+Z no terminal em que está executando o wget para suspendê-lo, e depois usando o comando fg para retomar a execução do processo.

    Testar o controle de congestionamento executando diversas instâncias do seu servidor, que escutem em portas distintas, e verificando se a banda é dividida igualmente entre os diversos clientes (wget) que se conectem a cada uma dessas portas.

# Parte III
Camada de Redes

O objetivo desta etapa é trabalhar um pouco com a camada de rede. Felizmente a implementação da camada de rede em um host costuma ser bastante simples, pois geralmente ele está conectado a um único roteador, o que torna a questão do encaminhamento de pacotes (que é a tarefa mais complexa atribuída à camada de rede) um problema trivial.

Nesta etapa, vamos exercitar duas tarefas relacionadas à camada rede:

    Interpretação de cabeçalhos IP.
    Reconstrução de datagramas IP fragmentados.

O código de exemplo fornecido para esta etapa gera pings com um grande payload destinados a um endereço definido na variável dest_addr. Uma sugestão para exercitar as tarefas acima é reconstruir a resposta ao ping que chegar de volta. Preste atenção aos seguintes pontos:

    O seu código deve conseguir funcionar mesmo que os fragmentos cheguem fora de ordem.
    Você deve implementar um timeout para desistir de remontar datagramas cujos fragmentos estejam demorando muito para chegar (e provavelmente tenham sido perdidos).

Mostre na tela informações sobre os datagramas remontados.


# Parte IV
Camada de Enlace

Modifique o código da Etapa 3 para utilizar um único socket do tipo socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)). Esse tipo de socket permite enviar e receber pacotes no nível da camada de enlace. Note que o socket não dá acesso a todas as informações da camada de enlace, por exemplo o CRC, mas apenas ao endereço MAC de destino, endereço MAC de origem e tipo do protocolo que está encapsulado dentro do quadro.

Utilize como base este código de exemplo. Modifique a função raw_recv para:

    Verificar se o endereço MAC de destino de cada quadro recebido é o MAC da sua placa de rede (variável src_mac).
    Verificar se o protocolo encapsulado dentro do quadro recebido é o protocolo IP (ETH_P_IF).
    Caso ambas as condições acima sejam satisfeitas, repassar o conteúdo encapsulado (datagrama IP) para uma função que lide com o processamento na camada de rede, por exemplo a função implementada na Etapa 3.


# Parte V
Integração

Integre o código das Etapas 2, 3 e 4, de forma que a partir de um único socket do tipo socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) seja possível obter a funcionalidade de servidor TCP que havia sido implementada na Etapa 2.


