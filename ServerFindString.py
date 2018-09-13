import socket, select, sys

def IsStringInText(string, text):
	stringIt = iter(string)
	textIt = iter(text)
	c = next(stringIt)
	while True:
		try:
			t = next(textIt)
		except:
			return False
		if t == c:
			try:
				c = next(stringIt)
			except:
				return True

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 8000))
s.listen(1)

if len(sys.argv) < 2:
	print("Passe a palavra que se quer achar como parametro")
	exit()

key = sys.argv[1]

while True:
	cli, addr = s.accept()
	#cli.setblocking(0) #?
	req = b''
	while True:
		#select.select(rlist, wlist, xlist, timeout=None)
		res_select = select.select([cli], [], [])
		# print("resultado do select: %r" % (res_select, ))
		req = cli.recv(1500)  #nao garante que vai receber tudo, usar um loop
		msg = req.decode()
		result = str(IsStringInText(key, msg))
		print(result, flush=True)
		resp = result.encode()
		cli.send(resp)

	cli.close()
