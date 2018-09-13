
#servidor TCP para camada de aplicacao usando socket


import socket

HOST='127.0.0.1'  #IP do Servidor reservado em qualquer maquina para verificar seus serviços / Addr do Servidor
PORT=7800            #PORT do servidor

# Criando conexao
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # .AF_INET -> indica conexao entre dois IPs ; .SOCK_STREAM -> indica conexao para familia TCP
s.bind((HOST, PORT)) # colocar os enderecos no socket para esperar conexao e ligar
s.listen(8)  #colocar socket para escutar na porta, "(x)"indica qtd de conexões q pode escutar

print('\niniciando servidor na IP: ', HOST, 'e Porta: ', PORT)
#configurando conexao
while True:
    cliente, addr = s.accept()
    print('cliente ', addr, 'conectado')

    while True:
        msg = cliente.recv(1024) #maximo de bytes q pode ser recebido nessa comunicacao
        if not msg:
            break
        #mostra mensagem recebida por cliente
        print('\nMensagem recebidad do Cliente:', addr)
        print('', msg.decode())

    print('fechando conexao do cliente ', addr)

    # encera conexao
    cliente.close()