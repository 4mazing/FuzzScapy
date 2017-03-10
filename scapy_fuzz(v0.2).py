#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.layers.inet import ICMP, TCP, IP

from scapy.all import *
from random import choice
import random
import os
import binascii

hello = "0300001611e00000001200c1020100c2020102c0010a"
set_comm = "0300001902f08032010000000000080000f0000001000101e0"
message_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"
ROSCTR_dict = {0: '01', 1: '07'}
userdata_dict = {0: '01', 1: '02', 2: '03', 3: '07'}
Group_funciton_dict = {
    1: {0: '01', 1: '02', 2: '0c', 3: '0e', 4: '0f', 5: '10', 6: '13'},
    2: {0: '01', 1: '04'},
    3: {0: '01', 1: '02', 2: '03'},
    4: {0: '01', 1: '02', 2: '03'},
    5: {0: '01'},
    6: {0: ''},
    7: {0: '01', 1: '02', 2: '03', 3: '04'}
}
Return_code_dict = {0: '00', 1: '01', 2: '03', 3: '05', 4: '06', 5: '07', 6: '0a', 7: 'ff'}
Transport_size_dict = {0: '00', 1: '03', 2: '04', 3: '05', 4: '06', 5: '07', 6: '09'}
testdata_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"


def randomString(n):
    random_string = (''.join(map(lambda xx: (hex(ord(xx))[2:]), os.urandom(n))))
    return random_string


def s7_fuzz_packet():
    ''' Create TPKT '''

    TPKT_Version = '03'
    TPKT_Reserved = '00'
    # TPKT_Length = randomString(1).zfill(2) + randomString(1).zfill(2)
    TPKT_Length = ((hex(random.randint(58, 60)))[2:]).zfill(4)
    TPKT = TPKT_Version + TPKT_Reserved + TPKT_Length

    ''' Create COTP '''

    COTP_Length = '02'
    # COTP_PDU_Type = ((hex(random.randint(0, 16)))[2:]) + '0'
    COTP_PDU_Type = 'f0'
    COTP_Last_data_unit = '80'
    COTP = COTP_Length + COTP_PDU_Type + COTP_Last_data_unit

    ''' Create S7-Head'''

    Protocol_ID = '32'
    ROSCTR = ROSCTR_dict[random.randint(0, 1)]
    Redundancy_Identification = '0000'
    Protocol_Data_Unit_Reference = randomString(2).zfill(4)
    Parameter_Length = '0008'
    Head_Data_Length = (
        hex(
            ((int(TPKT_Length, 16))*2 - 14 - 36)/2
        )[2:]).zfill(4)
    Header = Protocol_ID + ROSCTR + Redundancy_Identification + Protocol_Data_Unit_Reference\
             + Parameter_Length + Head_Data_Length

    ''' Create S7-Parameter '''

    Parameter_head = '000112'
    Parameter_length = '04'
    Parameter_Request = randomString(1).zfill(2)
    # Parameter_Type = str(random.randint(0, 16))
    Parameter_Type = (randomString(1))[0]
    Parameter_FunctionGroup = random.randint(1, 7)
    Parameter_subfunciton = choice(Group_funciton_dict[Parameter_FunctionGroup])
    Parameter_FunctionGroup = str(Parameter_FunctionGroup)
    Parameter_Sequence_number = randomString(1).zfill(2)
    Parameter = Parameter_head + Parameter_length + Parameter_Request + Parameter_Type + Parameter_FunctionGroup\
                + Parameter_subfunciton + Parameter_Sequence_number

    ''' Create S7-Data '''

    Data_ReturnCode = Return_code_dict[random.randint(0, 7)]
    Data_Transport_size = Transport_size_dict[random.randint(0, 6)]
    Data_Length = (
                      (int(Head_Data_Length, 16) * 2) - 8
                  )/2
    Data_Data = ''
    Data_Data = randomString(Data_Length).zfill(Data_Length * 2)
    Data_Length = (hex(Data_Length))[2:].zfill(4)
    Data = Data_ReturnCode + Data_Transport_size + Data_Length + Data_Data

    ''' the fuzz packet '''

    fuzz_pkt = TPKT + COTP + Header + Parameter + Data
    return fuzz_pkt


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
    '''这里的测试代码访问返回的数据包，确认了返回数据的长度'''
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
    fuzz_pkt = s7_fuzz_packet()
    print "-----------------------"
    # print fuzz_pkt
    # print len(fuzz_pkt)
    fuzz_pkt = str2byte(fuzz_pkt)
    syn_ack = tcpconnect()
    result = hello_plc(syn_ack)
    fuzz(fuzz_pkt)


