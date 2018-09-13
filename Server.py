import socket, select

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 8000))
s.listen(1)

print('\niniciando servidor na IP: ')
while True:
	cli, addr = s.accept()
	#cli.setblocking(0) #?
	req = b''
	while not b'\r\n\r\n' in req:
		#select.select(rlist, wlist, xlist, timeout=None)
		res_select = select.select([cli], [], [])
		# print("resultado do select: %r" % (res_select, ))
		req += cli.recv(1500)  #nao garante que vai receber tudo, usar um loop
	method, path, lixo = req.split(b' ', 2)
	if method == b'GET':
		texto = b" Ola " + path
	else:
		texto = b'Nao entendi\n'

	texto *= 500
	
	resp = b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(texto)
	resp += texto
	cli.send(resp)
	cli.close()
