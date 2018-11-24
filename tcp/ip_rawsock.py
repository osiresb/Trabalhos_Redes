import socket
import asyncio
import struct

class Ip:
 def __init__(self, version, hlen, service, tlen, identification, flags, foffset, ttl, protocol, checksum, source, destination, payload):
    self.version = version
    self.hlen = hlen
    self.service = service
    self.tlen = tlen
    self.id = identification
    self.flags = flags
    self.foffset = foffset
    self.ttl = ttl
    self.protocol = protocol
    self.checksum = checksum
    self.src = source
    self.dst = destination
    self.payload = payload


class Full_packet:
 def __init__(self, identification, ip):
    self.identification = identification
    self.ip_list = [ip]
full_packet_list = {}

def addr2str(addr):
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

ETH_P_IP = 0x0800

# Coloque aqui o endereço de destino para onde você quer mandar o ping
dest_addr = '1.1.1.1'


def send_ping(send_fd):
    print('enviando ping')
    # Exemplo de pacote ping (ICMP echo request) com payload grande
    msg = bytearray(b"\x08\x00\x00\x00" + 5000*b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))
    send_fd.sendto(msg, (dest_addr, 0))

    asyncio.get_event_loop().call_later(1, send_ping, send_fd)

def check_packet_is_full(ip_list):
    expected_offset = 0
    for ip in ip_list:
        if ip.foffset != expected_offset:
            return False
        if ip.flags == 0:
            return True
        expected_offset += ip.tlen / 8
    return False

def return_payload(ip_list):  
    complete_payload = bytearray()
    for ip in ip_list:
        complete_payload = complete_payload + ip.payload
    return complete_payload

def raw_recv(recv_fd):
    packet = recv_fd.recv(12000)
    print('recebido pacote de %d bytes' % len(packet))

    src_addr = addr2str(packet[12:16])
    dst_addr = addr2str(packet[16:20])
   
    version_hlen, service, tlen, identification, flags_foffset, ttl, protocol, checksum, source, destination = struct.unpack('!BBHHHBBHII', packet[:20])
    payload = packet[20:]
    flags = (flags_foffset & 0b1110000000000000) >> 13
    foffset = (flags_foffset & 0x1fff)
    version = (version_hlen & 0b11110000) >> 4
    hlen = (version_hlen & 0xf)

    ip = Ip(version, hlen, service, tlen, identification, flags, foffset, ttl, protocol, checksum, src_addr, dst_addr, payload)

    id_packet = (identification)

    if id_packet in full_packet_list:
        full_packet = full_packet_list[id_packet]
        full_packet.ip_list.append(ip)
        full_packet.ip_list.sort(key=lambda ip: ip[6])
        if check_packet_is_full(full_packet.ip_list):
            print('OK')
            complete_payload = return_payload(full_packet.ip_list)
            print(complete_payload)
    else:
        full_packet_list[id_packet] = Full_packet(identification, ip)
        full_packet = full_packet_list[id_packet]
        if check_packet_is_full(full_packet.ip_list):
            print('OK')
            complete_payload = return_payload(full_packet.ip_list)
            print(complete_payload)

    print(version)
    print(hlen)
    print(service)
    print(tlen)
    print(identification)
    print(flags)
    print(foffset)
    print(ttl)
    print(protocol)
    print(checksum)
    print(src_addr)
    print(dst_addr)
    
def calc_checksum(segment):
    if len(segment) % 2 == 1:
        # se for ímpar, faz padding à direita
        segment += b'\x00'
    checksum = 0
    for i in range(0, len(segment), 2):
        x, = struct.unpack('!H', segment[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff


if __name__ == '__main__':
    # Ver http://man7.org/linux/man-pages/man7/raw.7.html
    send_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Para receber existem duas abordagens. A primeira é a da etapa anterior
    # do trabalho, de colocar socket.IPPROTO_TCP, socket.IPPROTO_UDP ou
    # socket.IPPROTO_ICMP. Assim ele filtra só datagramas IP que contenham um
    # segmento TCP, UDP ou mensagem ICMP, respectivamente, e permite que esses
    # datagramas sejam recebidos. No entanto, essa abordagem faz com que o
    # próprio sistema operacional realize boa parte do trabalho da camada IP,
    # como remontar datagramas fragmentados. Para que essa questão fique a
    # cargo do nosso programa, é necessário uma outra abordagem: usar um socket
    # de camada de enlace, porém pedir para que as informações de camada de
    # enlace não sejam apresentadas a nós, como abaixo. Esse socket também
    # poderia ser usado para enviar pacotes, mas somente se eles forem quadros,
    # ou seja, se incluírem cabeçalhos da camada de enlace.
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    recv_fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))

    loop = asyncio.get_event_loop()
    loop.add_reader(recv_fd, raw_recv, recv_fd)
    asyncio.get_event_loop().call_later(1, send_ping, send_fd)
    loop.run_forever()

