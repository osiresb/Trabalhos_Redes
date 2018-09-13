#cliente TCP para camada de aplicacao usando socket

import socket

HOST='127.0.0.1'  #IP do Servidor
PORT=8000            #PORT do servidor

#criar conexao
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

print('Escreve a mensagem para enviar: \n')
msg = input()

while msg != '\x18':
    s.send(str(msg).encode()) # envia a msg digitada
    msg = input()


#encera conexao
s.close()
