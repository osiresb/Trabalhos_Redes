#!/usr/bin/python3
#
# Antes de usar, execute o seguinte comando para evitar que o Linux feche
# as conexões TCP abertas por este programa:
#
# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
#

import asyncio
import socket
import struct
import os
import random
import time

FLAGS_FIN = 1<<0
FLAGS_SYN = 1<<1
FLAGS_RST = 1<<2
FLAGS_ACK = 1<<4

MSS = 1460

TESTAR_PERDA_ENVIO = True

from array import *

class Conexao:
    def __init__(self, id_conexao, seq_no, ack_no):
        self.id_conexao = id_conexao
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.send_queue = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + 100000 * b"hello pombo\n"
        self.last_ack_sent = seq_no
        self.current_last_byte_sent = 0
        self.establ_con = False
        self.finish_con = False
        self.callback_handle = None
        self.time_send_index = 0
        self.time_recv_index = 0
        self.rtt_index = 0
        self.rtt_index_limit = 10
        self.alpha = 0.125
        self.est_rtt = 0.1
        self.time_send = array('d',[0,0,0,0,0,0,0,0,0,0])
        self.time_recv = array('d',[0,0,0,0,0,0,0,0,0,0])
        self.rtt = array('d',[0,0,0,0,0,0,0,0,0,0])
conexoes = {}



def addr2str(addr):
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

def str2addr(addr):
    return bytes(int(x) for x in addr.split('.'))

def handle_ipv4_header(packet):
    version = packet[0] >> 4
    ihl = packet[0] & 0xf
    assert version == 4
    src_addr = addr2str(packet[12:16])
    dst_addr = addr2str(packet[16:20])
    segment = packet[4*ihl:]
    return src_addr, dst_addr, segment


def make_synack(src_port, dst_port, seq_no, ack_no):
    return struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,
                       ack_no, (5<<12)|FLAGS_ACK|FLAGS_SYN,
                       1024, 0, 0)

def make_finack(src_port, dst_port, seq_no, ack_no):
    return struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,
                       ack_no, (5<<12)|FLAGS_FIN|FLAGS_ACK,
                       1024, 0, 0)

def make_ack(src_port, dst_port, seq_no, ack_no):
    return struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,
                       ack_no, (5<<12)|FLAGS_ACK,
                       1024, 0, 0)

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

def fix_checksum(segment, src_addr, dst_addr):
    pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + \
        struct.pack('!HH', 0x0006, len(segment))
    seg = bytearray(segment)
    seg[16:18] = b'\x00\x00'
    seg[16:18] = struct.pack('!H', calc_checksum(pseudohdr + seg))
    return bytes(seg)


def send_next(fd, conexao, bytes_to_send):
    (dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao

    last_byte_send = conexao.current_last_byte_sent
    payload = conexao.send_queue[last_byte_send:last_byte_send + bytes_to_send]
    if len(payload) == 0:
        return 0
    conexao.current_last_byte_sent += len(payload)

    segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.seq_no,
                          conexao.ack_no, (5<<12)|FLAGS_ACK,
                          1024, 0, 0) + payload

    conexao.seq_no = (conexao.seq_no + len(payload)) & 0xffffffff

    segment = fix_checksum(segment, src_addr, dst_addr)

    if not TESTAR_PERDA_ENVIO or random.random() < 0.95:
        fd.sendto(segment, (dst_addr, dst_port))

    return len(payload)

def send_batch(fd, conexao, window_size):
    bytes_sent = conexao.current_last_byte_sent
    num_last_bytes_sent = None
    while bytes_sent < window_size and num_last_bytes_sent != 0:
        bytes_to_send = min(window_size - bytes_sent, MSS)

        conexao.time_send[conexao.time_send_index] = time.time()
        conexao.time_send_index = (conexao.time_send_index + 1) % (conexao.rtt_index_limit)	
        num_last_bytes_sent = send_next(fd, conexao, bytes_to_send)
        bytes_sent += num_last_bytes_sent
    if num_last_bytes_sent == 0 and not conexao.finish_con:
        (dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao
        segment = make_finack(src_port, dst_port, conexao.seq_no, conexao.ack_no)
        segment = fix_checksum(segment, src_addr, dst_addr)
        fd.sendto(segment, (dst_addr, dst_port))
        conexao.finish_con = True

def retransmit_packets(fd, conexao):
    conexao.seq_no = (conexao.seq_no - conexao.current_last_byte_sent) & 0xffffffff
    conexao.current_last_byte_sent = 0
    send_batch(fd, conexao, conexao.cur_window_size)

def rtt_div(conexao):
    div = 0
    for i in range (0,conexao.rtt_index_limit):
        if conexao.rtt[i] != 0:
            div += 1
    return div

def raw_recv(fd):
    packet = fd.recv(12000)
    src_addr, dst_addr, segment = handle_ipv4_header(packet)
    src_port, dst_port, seq_no, ack_no, \
        flags, window_size, checksum, urg_ptr = \
        struct.unpack('!HHIIHHHH', segment[:20])

    id_conexao = (src_addr, src_port, dst_addr, dst_port)

    if dst_port != 7000:
        return

    payload = segment[4*(flags>>12):]

    if (flags & FLAGS_SYN) == FLAGS_SYN:
        print('%s:%d -> %s:%d (seq=%d)' % (src_addr, src_port,
                                           dst_addr, dst_port, seq_no))

        conexoes[id_conexao] = conexao = Conexao(id_conexao=id_conexao,
                                                 seq_no=struct.unpack('I', os.urandom(4))[0],
                                                 ack_no=seq_no + 1)

        fd.sendto(fix_checksum(make_synack(dst_port, src_port, conexao.seq_no, conexao.ack_no),
                               src_addr, dst_addr),
                  (src_addr, src_port))
    elif id_conexao in conexoes:
        conexao = conexoes[id_conexao]
        conexao.ack_no += len(payload)
        conexao.cur_window_size = window_size

        conexao.time_recv[conexao.time_recv_index] = time.time()
        conexao.time_recv_index = (conexao.time_recv_index + 1) % (conexao.rtt_index_limit)	
        if (conexao.time_recv[conexao.rtt_index] == 0) or (conexao.time_send[conexao.rtt_index] == 0):
            conexao.rtt[conexao.rtt_index] = 0.1
        else:
            conexao.rtt[conexao.rtt_index] = conexao.time_recv[conexao.rtt_index] - conexao.time_send[conexao.rtt_index]
        conexao.rtt_index = (conexao.rtt_index + 1) % (conexao.rtt_index_limit)
        conexao.est_rtt=(1-conexao.alpha)*conexao.est_rtt+conexao.alpha*sum(conexao.rtt)/rtt_div(conexao)
        if conexao.callback_handle:
            conexao.callback_handle.cancel()
        conexao.callback_handle = asyncio.get_event_loop().call_later(conexao.est_rtt, retransmit_packets, fd, conexao)
        if (flags & FLAGS_FIN) == FLAGS_FIN and ack_no == conexao.seq_no + 1:
            conexao.seq_no += 1
            conexao.ack_no += 1
            fd.sendto(fix_checksum(make_ack(dst_port, src_port, conexao.seq_no, conexao.ack_no),
                                   src_addr, dst_addr),
                      (src_addr, src_port))
        elif not conexao.establ_con and (flags & FLAGS_ACK) == FLAGS_ACK \
                and ack_no == conexao.seq_no + 1:
            conexao.establ_con = True
            conexao.seq_no += 1
            conexao.last_ack_sent += 1
            send_batch(fd, conexao, window_size)
        else:
            if ack_no > conexao.last_ack_sent:
                bytes_acked = ack_no - conexao.last_ack_sent
                conexao.last_ack_sent = ack_no
                conexao.current_last_byte_sent -= bytes_acked
                conexao.send_queue = conexao.send_queue[bytes_acked:]
                send_batch(fd, conexao, window_size)
    else:
        print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
            (src_addr, src_port, dst_addr, dst_port))



if __name__ == '__main__':
    fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv, fd)
    loop.run_forever()
