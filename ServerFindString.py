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

	while True:
		req = b''
		while not (b'\r\n\r\n' in req or b'\n\n' in req):
			pedaco = cli.recv(1500)
			if pedaco == b'':
				break
			req += pedaco
		if req == b'':
			break
		msg = req.decode()
		#print(msg)
		#print('requisição tem %d bytes' % len(msg))
		result = str(IsStringInText(key, msg))
		print(result, flush=True)
		resp = result.encode()
		cli.send(resp)

	cli.close()
