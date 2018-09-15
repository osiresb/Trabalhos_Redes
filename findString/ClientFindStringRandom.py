# Client that sends a random message to the server

import socket, string, random

HOST='127.0.0.1'
PORT=8000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

print('Escreva a quantidade de caracteres que se quer mandar: \n')
n = int(input())

while n != '\x18':
    msg = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))
    msg += "\r\n\r\n"
    s.send(str(msg).encode()) # sends the random message
    n = int(input())

s.close()
