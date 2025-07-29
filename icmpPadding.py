#!/usr/bin/python

from netfilterqueue import NetfilterQueue
from scapy.all import *


def isAnIP(string):
    address = sys.argv[1].split('.')
    numOctets = len(address)
    numValid = 0

    for i in range(0, numOctets):
        try:
            if int(address[i]) >= 0 and int(address[i]) < 256:
                numValid += 1
            else:
                return False
        except ValueError:
            return False

    if numValid < numOctets or numOctets != 4:
        return False
    else:
        return True


def process(pkt):

    #declaration of global variables
    global idxSnd
    global rcvIdNum
    global sndIdNum
    global rcvSeqNum
    global sndSeqNum
    global clearToSend
    global origIcmpData

    #conversion to a Scapy packet
    scapyPkt = IP(pkt.get_payload())

    #check if Scapy packet has ICMP and Raw layers
    if scapyPkt.haslayer('ICMP') and scapyPkt.haslayer('Raw'):

        #steps for both received and sent packets
        #acquisition of data after Seq Num field and data type conversion
        icmpData = list(scapyPkt[Raw].load)


        #steps for received packets
        if scapyPkt[IP].src == sys.argv[1]:

            #acquisition of ICMP Identifier and Sequence number
            rcvIdNum = scapyPkt[ICMP].id
            rcvSeqNum = scapyPkt[ICMP].seq

            #acquisition of secret message from ICMP Data field
            #offset of 16 bytes since Scapy dissects timestamp to ICMP Data field
            rcvMessage = ''.join(chr(i) for i in icmpData[16:16+lenPart])

            #check if next Echo Request could be used for injection of secret message
            if rcvIdNum == sndIdNum and rcvSeqNum == sndSeqNum:
                if rcvMessage == origIcmpData:
                    if idxSnd == 0:
                        clearToSend = True
                    else:
                        clearToSend = False
            else:
                clearToSend = False

            #masking content of ICMP Data field with original content
            #masking is applied only for Echo Replies that are results of
            #Echo Request from this machine
            if rcvSeqNum == sndSeqNum:
                icmpData[16:16+len(origIcmpData)] = [ord(i) for i in origIcmpData]


        #steps for sent packets
        elif scapyPkt[IP].dst == sys.argv[1]:

            #acquisition of ICMP Identifier and Sequence number
            sndIdNum = scapyPkt[ICMP].id
            sndSeqNum = scapyPkt[ICMP].seq

            if clearToSend:
                #choice of secret message part
                if idxSnd < numParts:
                    sndMessage = splitMessage[idxSnd]
                    idxSnd += 1
                else:
                    sndMessage = origIcmpData

                #injection of secret message to ICMP Data field behind the timestamp
                icmpData[16:16+len(sndMessage)] = [ord(i) for i in sndMessage]


        #steps for both received and sent packets
        #data type conversion
        modifIcmpData = bytes(icmpData)

        #replacement of Raw layer payload
        scapyPkt[Raw].remove_payload()
        scapyPkt[Raw].load = modifIcmpData

        #recalculation of IP packet length and ICMP checksum
        del scapyPkt[ICMP].chksum


    #conversion to a NetfilterQueue object and forwarding
    pkt.set_payload(bytes(scapyPkt))
    pkt.accept()


#check for number of arguments
if len(sys.argv) != 3:
    print('Unsupported number of arguments!\nThe correct syntax is solution3.py <destination IP address> <secret message>')
    sys.exit(1)

#check for destination IP address validity
if not isAnIP(sys.argv[1]):
    print('Destination IP address is not valid!')
    sys.exit(1)


#parsing message to a variable
message = sys.argv[2]
numChars = len(message)

#division of message to parts
#with length of 40 bytes
lenPart = 40
numParts = math.ceil(numChars / lenPart)
splitMessage = [message[i:i+lenPart] for i in range(0, numChars, lenPart)]
print('Secret message has ' + str(numChars) + ' characters, which would be injected into ' + str(numParts) + ' ICMP Echo Request messages.\nThe script could be ended by pressing Ctrl+C.')


#definition of original content of ICMP Data field
origIcmpData = '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'

#preallocation of used indexes
idxSnd = 0
rcvIdNum = 0
sndIdNum = 0
rcvSeqNum = 0
sndSeqNum = 0

#preallocation of a flag for sending secret message
clearToSend = False


#establishing iptables rules and NetfilterQueue queues
os.system('sudo iptables -A INPUT -s ' + sys.argv[1] + ' -p icmp --icmp-type 0 -j NFQUEUE --queue-num 1; sudo iptables -A OUTPUT -d ' + sys.argv[1] + ' -p icmp --icmp-type 8 -j NFQUEUE --queue-num 1; sleep 1')
nfqueue = NetfilterQueue()
nfqueue.bind(1, process)

#running the queue
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

#ending the queue and disabling iptables rules
nfqueue.unbind()
os.system('sleep 1; sudo iptables -D OUTPUT -d ' + sys.argv[1] + ' -p icmp --icmp-type 8 -j NFQUEUE --queue-num 1; sudo iptables -D INPUT -s ' + sys.argv[1] + ' -p icmp --icmp-type 0 -j NFQUEUE --queue-num 1')
