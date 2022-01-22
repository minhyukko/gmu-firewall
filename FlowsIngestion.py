
import os
import json
import scapy.all as scapy
from xml.etree import ElementTree
import binascii
import socket
import math

import sys
import getopt

import cv2
import numpy
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy import compat

class FlowTime:# Time Object To allow comparison from Flow Formatting to a comparable time object
    def __init__(self, t):
        self.day = int(t[8:10])
        self.hour = int(t[11:13])
        self.min = t[14:16]
        self.sec = t[17:19] 

    def __lt__(self, other):
        if self.day == other.day:
            if self.hour == other.hour:
                if self.min  == other.min:
                    if self.sec < other.sec:
                        return True
                    else:
                        return False
                elif self.sec < other.sec:
                    return True
                else:
                    return False

            elif self.hour < other.hour:
                return True
            else:
                return False
        elif self.day < other.day:

            return True
        else:
            return False
    def __repr__(self):# String representation of time used for saving in json
        ans = ""
        ans += str(self.day) + "T"
        ans+= str(self.hour) + ":"
        ans += str(self.min) + ":"
        ans += str(self.sec)
        return ans

class FlowNode:#Linked List Node used within hashmap
    def __init__(self, source, destination, total_num_packets, source_num, destination_num, startDateTime, tag, key):# Attributes in Node correspond to FLow attributes from the XML
        self.source = source# Source IP Address
        self.destination = destination# Destination IP Address
        self.key = key
        self.total_num_packets = total_num_packets # Total number of packets in each flow if zero go to next element in linked list
        self.source_num = source_num# number of source packets (Source->Destination)
        self.destination_num = destination_num# number of destination packets (Destination->Source)
        self.startDateTime = FlowTime(startDateTime)
        self.packets = []# List of binary strings representing each packet
        self.tag = tag# Benign or Malicious attack type of tcp flow
        self.next = None# The Next Node

    def __repr__(self):#String representation of Node used for debugging
        return "Tag: " + str(self.tag)

def pkt_to_bin(pkt):
    line_length = 0;
    file_num=0
    image_arr =[]
    i=0
    
    if pkt.haslayer("IP"):
        if pkt.haslayer("TCP"):
            #print(pkt[TCP].payload)
            pkt.remove_payload()
            #print (pkt)
        elif pkt.haslayer("UDP"):
            pkt.remove_payload()
            #print(pkt)
        else:
            pkt.remove_payload()
            #print (pkt)
    pkt_hex=compat.bytes_hex(pkt)
    #print(pkt_hex)
    pkt_bin = bin(int.from_bytes(pkt_hex, byteorder=sys.byteorder))
    pkt_final= pkt_bin[2:]
    return pkt_final


size = 110513#Constant size used for hashmap



def writeJSON(flow, count, attack):# Saves Completed Flow Node into json formatting
    flow_dic = {}
    flow_dic['total_num_packets'] = flow.total_num_packets
    flow_dic['source'] = flow.source
    flow_dic['destination'] = flow.destination  
    flow_dic['startDateTime'] = str(flow.startDateTime)
    flow_dic['packets'] = flow.packets 
    flow_dic['Tag'] = flow.tag
    flow_dic['key'] = flow.key
    flow_dic['name'] = './flows/Flow_' + str(count) + '_attack_' + attack + ".json"
    print("Writing JSON Name: ",flow_dic['name'])
    with open(flow_dic['name'], 'w') as f:
        json.dump(flow_dic, f)
        f.close()
    return


class HashMap:#Hashmap that holds a linked list of FlowNodes at each index
    def __init__(self, size, attack):
        self.size = size# Size of hashmap
        self.arr = [None] * self.size# Create array that i
        self.attack = attack# Attack type for the days Flow
        self.count = 0#Current Number of completed flows used for json naming

    def add(self, flow):#Add new node to the hashmap
       # print("Adding")
        key = flow[dic['source']] + flow[dic['destination']]
        key = hash(key)
        if key < 0 :
            key *= -1
        tag = "Normal" if flow[dic['Tag']] == 'Normal' else self.attack
        fn = FlowNode(flow[dic['source']], flow[dic['destination']], int(flow[dic['totalDestinationBytes']]) + int(flow[dic['totalSourceBytes']]), int(flow[dic['totalSourceBytes']]), int(flow[dic['totalDestinationBytes']]), flow[dic['startDateTime']], tag, key)
        pos = key % self.size

        if self.arr[pos] == None:
            self.arr[pos] = fn
        else:
            node = self.arr[pos]
            while(not (node == None)):
                if(node.next == None):
                    node.next = fn
                    break
                node = node.next

    def addPacket(self, pkt):#Adds a packet to the corresponding flow
        source = pkt['IP'].src
        destination = pkt['IP'].dst
        key = source + destination 
        #print("Key: ", key)
        key = hash(key)
        add = None
        o = False
        t = False
        if key < 0:
            key *= -1
        pos = key % self.size


        key2 = destination + source
        key2 = hash(key2)
        if key2 < 0:
            key2 *= -1
        pos2 = key2 % self.size

        one = self.arr[pos]
        if not (one == None):
            o = True
            if not one.key == key:
                while(not one.next == None):
                    if one.next.key == key and one.source_num > 0:
                        one = one.next
                        break
                    one = one.next
            if one.source_num > 0:
                one.source_num -= 1
                one.total_num_packets -= 1
                if one.total_num_packets == 0:
                    self.remove(one.key)
        two = self.arr[pos2]
        if not (two == None):
            t = True
            if not two.key == key:
                while(not two.next == None):
                    if two.next.key == key and two.destination_num > 0:
                        two = two.next
                        break
                    two = two.next
            if two.destination_num > 0:
                two.destination_num -= 1
                two.total_num_packets -= 1
                if two.total_num_packets == 0:
                    self.remove(two.key)
        if o == True and t == True:
            if one.startDateTime < two.startDateTime: 
                add = one
            else:
                add = two
        elif o == True and t == False:
            add = one 
        elif t == True and o == False:
            add = two
       # print("Add: ",add)
        if add == None:
            print("Failed")
            return
        add.packets.append(pkt_to_bin(pkt))# Append Bits


    def remove(self, key):#Removes a flow and saves the flow in json format
        temp = None
        pos = key % self.size
        if self.arr[pos] == None:
            return False
        if self.arr[pos].key == key:
            #do stuff
            writeJSON( self.arr[pos], self.count, self.attack)
            self.arr[pos] = self.arr[pos].next
            self.count += 1
            return True
        elif not self.arr[pos].next == None:
            temp = self.arr[pos]
            #writeJSON(temp)
            self.arr[pos] = self.arr[pos].next
            while not (temp == None):
                if temp.key == key:
                    writeJSON(temp, self.count, self.attack)
                    self.count += 1
                    temp = temp.next
                    return True
                if temp.next == None:
                    return False
                temp = temp.next
            self.arr[pos] = None
        else:
            return False

    def __repr__(self):#String representation of hashmap used for testing
        ans = ""
        for i in range(len(self.arr)):
            if self.arr[i] == None:
                continue
            else:
                temp = self.arr[i]
                ans += "[" + str(i) + "]Head>"
                while(not (temp == None)):
                    ans += " > "
                    ans += temp.source + " " + temp.destination + " " + str(temp.startDateTime)
                    temp = temp.next
            ans += "\n"
        return ans




#End of Setting up hashtable/LinkedList Nodes


fname = 'TestbedSunJun13Flows.xml'
xml = ElementTree.parse(fname)
inputs = xml.findall('TestbedSunJun13Flows')

print(inputs[0:5])
vals = ['appName', 'totalSourceBytes', 'totalDestinationBytes', 'totalDestinationPackets','totalSourcePackets', 'sourcePayloadAsBase64','sourcePayloadAsUTF','direction','sourceTCPFlagsDescription', 'source','protocolName', 'sourcePort', 'destination','destinationPort','startDateTime','stopDateTime','Tag']
dic = {}#Allows to get index from XML identifier using the identifier name
for i in range(len(vals)):
    dic[vals[i]] = i
#print(dic)

List = []

for f in inputs:
    x = []
    #print(f)
    for y in vals:
        x.append(f.find(y).text)
    List.append(x)
#print(List[0:4])

hm = HashMap(110513, "Infiltrating_Transfer")

#print(List)
l = []
cc = 0
for i in range(len(List)-1, -1, -1):
    if List[i][dic['protocolName']] == 'tcp_ip':
        continue
    else:
        List.pop(i)
#print("Current Size: ", len(List))
for flow in List:
    #print("Here")
    hm.add(flow)
    l.append(flow[dic['source']] + flow[dic['destination']])
    #print("Source: ", flow[dic['source']], "Destination: ",flow[dic['destination']] )
    #print(l[-1])
    cc += 1
count = 0
for i in hm.arr:
    if not (i == None):
        temp = i
        count += 1
        while not (temp == None):
            temp = temp.next
            count += 1
print("Number of Flows: ", len(List), " Number of Flows Added: ", count)
#print("Size of List: ", len(List))
'''print(l)
for i in l:
    h = hash(i)
    if h < 0:
        h *= -1
    print("Hash: ", h)
    print("Pos: ", h % hm.size)
   
    print("Next: ", hm.arr[h % hm.size].next)
print("---------------------------------------")
print(hm)
print(l[0])
hm.remove((hash(l[0])*-1) if hash(l[0]) < 0 else hash(l[0]))
print(hm)
hm.remove((hash(l[0])*-1) if hash(l[0]) < 0 else hash(l[0]))
print(hm)
hm.remove((hash(l[0])*-1) if hash(l[0]) < 0 else hash(l[0]))
print(hm)
'''

#print("\n\n")
#print(hm)
#print("\n\n")
def packet_values(pkt):#Read packet by packet from pcap and compare values
    global hm
    num_in_list_1 = 0
    if 'IP' not in pkt:
        return True
    if 'TCP' not in pkt:
        return True
    key = pkt['IP'].src + pkt['IP'].dst
    #for x in List:
     #   key2 = x[dic['source']] + x[dic['destination']]
      #  if key == key2:
            #print("Found Match")
       #     break

    #pkt.show()
    hm.addPacket(pkt)

    total = 0
    return True


f = scapy.sniff(offline="testbed-13jun.pcap", prn=packet_values, store=0)#Reads in 4 packets from pcap file passed in

