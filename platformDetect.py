#!/usr/bin/env python3

from scapy.all import *
from math import floor
from sys import argv, exit


def check(srcIP, srcIface):

    #capturing two ICMP Echo Request messages by Scapy
    captReqs = sniff(iface = srcIface, filter = 'icmp and src host ' + srcIP, count = 2)

    #acquisition of ICMP Echo Request message lengths
    lengths = [None] * 2
    for i in range(2):
        #only if Scapy dissected messages have Raw layers
        if captReqs[i].haslayer('Raw'):
            lengths[i] = len(captReqs[i][Raw])
        else:
            print('At least one of the captured ICMP Echo Request messages does not have Scapy Raw layer!')
            exit(1)

    #if Raw lengths are the same sizes and longer than 0
    if len(set(lengths)) == 1 and lengths[0] > 0:

        #preallocating variables
        msgStart = 0
        msgLength = 0

        #changing data types
        lists = {}
        lists = [list(captReqs[0][Raw].load), list(captReqs[1][Raw].load)]

        #making a difference vector/ list
        diffList = []
        for i in range(lengths[0]):
            diffList.append(abs(lists[0][i] - lists[1][i]))

        #checking differences in bytes
        diffBytes = []
        for i in range(0, 8*floor(lengths[0]/8), 8):
            diffBytes.append(sum(diffList[i:i + 8]))

        #searching the first byte without difference
        if 0 in diffBytes:
            msgStart = diffBytes.index(0)
            msgLength = floor(lengths[0]/8) - msgStart

        return msgStart, msgLength

    else:
        print('The ICMP Echo Request messages have either different lengths or the first one has invalid length!')
        exit(1)


#check for number of arguments
if len(argv) != 3:
    print('Unsupported number of arguments!\nThe correct syntax is platformDetect.py <capturing IP address> <capturing interface>')
    exit(1)

try:
    #checking message offset and length
    msgStart, msgLength = check(argv[1], argv[2])
    print('Message starts after byte ' + str(8*msgStart) + ' and packet(s) contain up to ' + str(8*msgLength) + ' bytes of message.')

except KeyboardInterrupt:
    print('')
