#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.all import *
import random
import os
import binascii

''' S/SA/A/PA/R'''
flags = {0: 2L, 1: 18L, 2: 16L, 3: 24L, 4: 4L}
fuzzlog = open('fuzzlog.log', 'w+')
sniffer = sniff(filter="tcp and host 172.18.15.108", timeout=20)
count = 0
while True:
    for i in range(len(sniffer)):
        flags = sniffer[i][2].flags
        if flags == 2L:
            fuzzlog.write(" %s "
                          " %s \n"
                          % (sniffer[i][1].src, flags)
                          )
        elif flags == 24L:
            data = binascii.hexlify(sniffer[i][3].load)
            fuzzlog.write(" %s "
                          " %s "
                          " %s \n"
                          % (sniffer[i][1].src, flags, data)
                          )
        elif flags == 18L:
            fuzzlog.write(" %s "
                          " %s \n"
                          % (sniffer[i][1].src, flags)
                          )
        elif flags == 16L:
            fuzzlog.write(" %s "
                          " %s \n"
                          % (sniffer[i][1].src, flags)
                          )
        elif flags == 4L:
            fuzzlog.write(" %s "
                          " %s \n"
                          % (sniffer[i][1].src, flags)
                          )
        else:
            pass
        count += 1




