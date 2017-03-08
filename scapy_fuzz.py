#!/usr/bin/python
# -*- coding: utf-8 -*-


from scapy.all import *
from scapy.layers.inet import ICMP, TCP
import random
import os
import binascii


hello = "0300001611e00000001200c1020100c2020102c0010a"
set_comm = "0300001902f08032010000000000080000f0000001000101e0"
message_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"
userdata_dict = {0: '01', 1: '02', 2: '03', 3: '07'}
subfunction_dict = {0: '01', 1: '02', 2: '0c', 3: '0e', 4: '0f', 5: '10', 6: '13'}
testdata_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"


def randomString(n):
    return (''.join(map(lambda xx : (hex(ord(xx))[2:]), os.urandom(n))))[0:16]


def s7head():
    tpkt = message_str[:8]
    cotp = message_str[8:14]
    replay_header_part1 = message_str[14:26]
    replay_headpara = randomString(2).zfill(4)
    replay_headdata = randomString(2).zfill(4)
    replay_header = tpkt + cotp + replay_header_part1 + replay_headpara + replay_headdata
    return replay_header


def s7para():
    parameter_head = message_str[34:40]
    parameter_len = message_str[40:45]
    function_group = str(random.randint(1, 7))
    subfunction = subfunction_dict[random.randint(0, 6)]
    sequence_number = message_str[48:50]
    replay_parameter = parameter_head + parameter_len + function_group + subfunction + sequence_number
    return replay_parameter


def s7data():
    return_code = message_str[50:52]
    transport_size = message_str[52:54]
    data_len = randomString(2).zfill(4)
    data = randomString(4).zfill(8)
    replaydata = return_code + transport_size + data_len + data
    return replaydata


def str2byte(data):
    base = '0123456789ABCDEF'
    i = 0
    data = data.upper()
    result = ''
    while i < len(data):
        beg = data[i]
        end = data[i+1]
        i += 2
        b1 = base.find(beg)
        b2 = base.find(end)
        if b1 == -1 or b2 == -1:
            return None
        result += chr((b1 << 4) + b2)
    return result


def tcpconnect():

    ''' TCP HandShack'''
    # SYN
    SYN = TCP(sport=sport, dport=dport, flags='S', seq=0)
    SYNACK = sr1(ip/SYN)
    # print SYNACK

    # ACK
    ACK = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    send(ip/ACK)
    return SYNACK


def hello_plc(self):
    ''' ShakeHand with PLC'''
    # say hello
    hello_data = str2byte(hello)
    hello_packet = TCP(sport=sport, dport=dport, flags='PA', seq=self.ack, ack=self.seq + 1)
    COTPACK = sr(ip/hello_packet/hello_data, multi=True, timeout=5)
    # print COTPACK[0][1]

    comm_data = str2byte(set_comm)
    comm_pkt = TCP(sport=sport, dport=dport, flags='PA',
                   seq=COTPACK[0][1][1].ack, ack=COTPACK[0][1][1].seq + len(COTPACK[0][1][1].load))
    COMMACK = sr(ip / comm_pkt / comm_data, multi=True, timeout=5)
    # print COMMACK[0][1]

    # communication ack
    comm_ack = TCP(sport=sport, dport=dport, flags='A',
                   seq=COMMACK[0][2][1].ack, ack=COMMACK[0][2][1].seq + len(COMMACK[0][2][1].load))
    # print comm_ack.ack
    send(ip/comm_ack)
    return COMMACK


def fuzz(self):

    fuzzpkt = TCP(sport=sport, dport=dport, flags='PA',
                  seq=result[0][1][1].ack,
                  ack=result[0][1][1].seq + len(result[0][1][1].load))
    fuzzsr = sr(ip/fuzzpkt/self, multi=True, timeout=5)


# VARIABLES
src = sys.argv[1]
dst = sys.argv[2]
dport = int(sys.argv[3])

while True:
    sport = random.randint(1024, 65535)
    ip = IP(src=src, dst=dst)
    replay_pkt = s7head() + s7para() + s7data()
    fuzzdata = str2byte(replay_pkt)
    # os.system("python /root/GitPro/STGitPro/Fuzz/fuzz_sniff.py")
    syn_ack = tcpconnect()
    result = hello_plc(syn_ack)
    fuzz(fuzzdata)
    time.sleep(5)
    # print replay_pkt





