# Client that sends literal message to the server

import socket

HOST='127.0.0.1'
PORT=8000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

print('Escreve a mensagem para enviar: \n')
msg = input()

while msg != '\x18':
    msg += "\r\n\r\n"
    s.send(str(msg).encode()) # sends the message
    msg = input()

s.close()
