#!/usr/bin/env python3

from scapy.all import *
from math import floor
from sys import argv, exit


def check(srcIP, dstIface):

    #capturing two ICMP Echo Reply messages by Scapy
    captReps = sniff(iface = dstIface, filter = 'icmp and src host ' + srcIP, count = 2)

    #acquisition of ICMP Echo Reply message lengths
    lengths = [None] * 2
    for i in range(2):
        #only if Scapy dissected messages have Raw layers
        if captReps[i].haslayer('Raw'):
            lengths[i] = len(captReps[i][Raw])
        else:
            print('At least one of the captured ICMP Echo Reply messages does not have Scapy Raw layer!')
            exit(1)

    #if Raw lengths are the same sizes and longer than 0
    if len(set(lengths)) == 1 and lengths[0] > 0:

        #preallocating variables
        msgStart = 0
        msgLength = 0
        origData = []

        #changing data types
        lists = {}
        lists = [list(captReps[0][Raw].load), list(captReps[1][Raw].load)]

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

        #extracting data from first ICMP Echo Reply message
        #used for locating the end of secret message
        origData = lists[0]

        return msgStart, msgLength, origData

    else:
        print('The ICMP Echo Reply messages have either different lengths or the first one has invalid length!')
        exit(1)


def stopCapture(pkt):

    #declaration of global variables
    global msgStart, msgLength, origData, msgTransm, idxPkt, lastPkt

    #comparison of bytes in a pair of ICMP Echo Reply messages
    #only if two ICMP Echo Reply messages are captured and they both have Raw layers
    if pkt.haslayer('Raw'):

        #extraction of secret message data from following messages
        #conversion of data types
        lists = {}
        lists = [list(origData), list(pkt[Raw].load)]

        #extraction of possible secret message data
        extrLists = {}
        extrLists = [lists[0][8*msgStart:8*(msgStart + msgLength)], lists[1][8*msgStart:8*(msgStart + msgLength)]]

        #making a difference vector/ list of extracted possible secret messages
        diffList = []
        for i in range(8*msgLength):
            diffList.append(abs(extrLists[0][i] - extrLists[1][i]))

        #if there is not a difference, the secret message has already ended
        if msgTransm == True and sum(diffList) == 0:
            lastPkt = idxPkt
            return True
        #if there is a difference, next packet is checked
        else:
            idxPkt = idxPkt + 1

        if sum(diffList) != 0:
            msgTransm = True


def extractMsg(capt, lastPkt, msgStart, msgLength, origData):

    #message is extracted only if it is londer than 0 bytes
    if msgLength > 0:

        #conversion of data types and extraction of secret message data
        lists = {}
        extrLists = {}
        origDataLists = {}

        #storing number of captured packets
        numPkts = len(capt)

        #extraction of possible secret message data from packets
        for i in range(numPkts):
            lists[i] = list(capt[i][Raw].load)
            extrLists[i] = lists[i][8*msgStart:]
            origDataLists[i] = origData[8*msgStart:]

        #making difference vectors/ lists for marking secret message start and end
        diffLists = {}
        for i in range(numPkts):
            diffLists[i] = []
            for j in range(8*msgLength):
                diffLists[i].append(abs(extrLists[i][j] - origDataLists[i][j]))

        #marking a packet where extraction starts
        diffPkts = []
        for i in range(numPkts):
            diffPkts.append(sum(diffLists[i]))

        #looking for the last packet with zeros in difference vector (it is the same
        #as the original data) where the secret message begins
        startMsgPkt = 0
        for i in range(numPkts - 1):
            if diffPkts[i] == 0 and diffPkts[i + 1] != 0:
                startMsgPkt = i + 1

        #looking for the first packet with zeros in difference vector after non-zero
        #packets where the secret message ends
        endMsgPkt = 0
        for i in range(numPkts - 1, 1, -1):
            if diffPkts[i] == 0 and diffPkts[i - 1] != 0:
                endMsgPkt = i - 1

        #looking for the last continuous sequence of zeros in difference vector
        #and establishing an end message byte
        endMsgByte = 8*msgLength
        for i in range(8*msgLength - 1, 0, -1):
            if diffLists[endMsgPkt][i] == 0 and diffLists[endMsgPkt][i - 1] != 0:
                endMsgByte = i

        #extracting secret message from chosen packets
        extrMsgLists = {}
        for i in range(startMsgPkt, endMsgPkt):
            extrMsgLists[i] = extrLists[i]

        #the last packet might not have secret message in whole field
        extrMsgLists[endMsgPkt] = extrLists[endMsgPkt][:endMsgByte]

        #joining multiple lists into one list with extracted secret message
        extrMsgList = sum(list(extrMsgLists.values()), [])

        #conversion to a string
        extrMsg = ''
        extrMsg = extrMsg.join(chr(i) for i in extrMsgList)
        return extrMsg

    else:
        print('It is not possible to extract secret message if its start and length was not successfully detected!')
        exit(1)


#check for number of arguments
if len(argv) != 3:
    print('Unsupported number of arguments!\nThe correct syntax is platformReceive.py <capturing IP address> <capturing interface>')
    exit(1)

try:
    #checking message offset and length
    msgStart, msgLength, origData = check(argv[1], argv[2])
    print('Message starts after byte ' + str(8*msgStart) + ' and packet(s) contain up to ' + str(8*msgLength) + ' bytes of message.')

    #preallocation used variables
    idxPkt = 0

    #preallocation of a flag for secret message status
    msgTransm = False

    #packet capture by Scapy
    captPkts = sniff(iface = argv[2], filter = 'icmp and src host ' + argv[1], stop_filter = stopCapture)

    #script is ended if the capture does not contain at least 2 packets
    if len(captPkts) < 2:
        print('Unable to capture at least 2 packets without differences, the script is ending!')
        exit(1)

    else:
        #displaying extracted message in console
        extrMessage = extractMsg(captPkts, lastPkt, msgStart, msgLength, origData)
        print('Extracted secret message is: ' + extrMessage)

except KeyboardInterrupt:
    print('')
