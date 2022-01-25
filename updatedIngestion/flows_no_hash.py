
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

def pkt_to_bin(pkt):# Converts passed in packet into binary string
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
    flow_dic['name'] = './Flows22/Flow_' + str(count) + '_attack_' + attack + ".json"
    with open(flow_dic['name'], 'w') as f:
        json.dump(flow_dic, f)
        f.close()
    return


class HashMap:#Hashmap that holds a linked list of FlowNodes at each index
    def __init__(self, size, attack):
        self.size = size# Size of hashmap
        self.arr = []# Create array that i
        self.attack = attack# Attack type for the days Flow
        self.count = 0#Current Number of completed flows used for json naming

    def add(self, flow):#Add new node to the list
        key = flow[dic['source']] + flow[dic['destination']]
        key = hash(key)
        if key < 0 :
            key *= -1
        tag = "Normal" if flow[dic['Tag']] == 'Normal' else self.attack
        fn = FlowNode(flow[dic['source']], flow[dic['destination']], int(flow[dic['totalDestinationBytes']]) + int(flow[dic['totalSourceBytes']]), int(flow[dic['totalSourceBytes']]), int(flow[dic['totalDestinationBytes']]), flow[dic['startDateTime']], tag, key)
        self.arr.append(fn)# Adds the created FlowNode to the end of the array
    def containsFlow(self, key):# Ignore
        pos = key % self.size
        temp = self.arr[pos]
        global List
        if temp == None:
            print()
            return False

        else:
            if temp.key == key:
                return True
            else:
                while not (temp == None):
                    if temp.key == key:
                        return True
                    temp = temp.next
        print("Not Found")
        return False#End Ignore

    def getFlow_s(self, key):# Flow to check for source to destination packets in the array
        for i in range(len(self.arr)):
            if self.arr[i].key == key:
                if self.arr[i].source_num > 0:
                    return i 

        return None
    def getFlow_d(self, key):# Flowto check for destination to source packets in the array
        for i in range(len(self.arr)):
            if self.arr[i].key == key:
                if self.arr[i].destination_num > 0:
                    return i 

        return None
    def addPacket(self, pkt):#Adds a packet to the corresponding flow
        global l
        source = pkt['IP'].src
        destination = pkt['IP'].dst
        key = source + destination 
        key = hash(key)

        add = None

        o = False
        t = False
        if key < 0:
            key *= -1
        key2 = destination + source
        key2 = hash(key2)
        if key2 < 0:
            key2 *= -1


        one = self.getFlow_s(key)# Check to see if packet has spot in a flow source->destination
        two = self.getFlow_d(key2)# Check to see if packet has a spot in a flow from destination->source
        add = None

        if (not(one == None)) and (not(two == None)):# If both are not none pick the one with the earliest time
            if self.arr[one].startDateTime < self.arr[two].startDateTime:
                add = one
                self.arr[one].source_num -= 1 
                self.arr[one].total_num_packets -= 1
            else:
                add = two
                self.arr[two].destination_num -= 1
                self.arr[two].total_num_packets -= 1

        elif (not(one == None)):# If two is none but one is not packet should be added to flow in positiion one
            add = one
            self.arr[one].source_num -= 1 
            self.arr[one].total_num_packets -= 1

        elif (not(two == None)):# If one is none but two is not packet should be added to flow in positiion one
            add = two
            self.arr[two].destination_num -= 1
            self.arr[two].total_num_packets -= 1


        if add == None:# If still None failed to add packet
            return
        self.arr[add].packets.append(pkt_to_bin(pkt))# Add the binary packet to the specified flow

        if self.arr[add].total_num_packets == 0:# if the flow currently has no space availiable for new packets remove it.
            self.remove(add)


    def remove(self, pos):#Removes a flow and saves the flow in json format
        global List 
        cc = 0
        temp = None
        if self.arr[pos] == None:
            return False
        if pos >= 0:
            #do stuff
            writeJSON( self.arr[pos], self.count, self.attack)
            self.arr.pop(pos)
            self.count += 1
            return True
        
        return False


    def __repr__(self):#String representation of hashmap used for testing - Ignore wont work for list format
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
        return ans# End Ignore




#End of Setting up hashtable/LinkedList Nodes


fname = 'TestbedSunJun13Flows.xml'
xml = ElementTree.parse(fname)
inputs = xml.findall('TestbedSunJun13Flows')

#print(inputs[0:5])
vals = ['appName', 'totalSourceBytes', 'totalDestinationBytes', 'totalDestinationPackets','totalSourcePackets', 'sourcePayloadAsBase64','sourcePayloadAsUTF','direction','sourceTCPFlagsDescription', 'source','protocolName', 'sourcePort', 'destination','destinationPort','startDateTime','stopDateTime','Tag']
dic = {}#Allows to get index from XML identifier using the identifier name
for i in range(len(vals)):# set up dicitonary letting for easier attribute finding from xml flows
    dic[vals[i]] = i

List = []

for f in inputs:# Loop through flows in xml and append each one to a list
    x = []
    #print(f)
    for y in vals:
        x.append(f.find(y).text)
    List.append(x)
#print(List[0:4])

hm = HashMap(110513, "Infiltrating_Transfer")# Create List object In this senario its a List not hashmap

l = []
cc = 0
for i in range(len(List)-1, -1, -1):# Loop through removing any flows that are not tcp_ip
    if List[i][dic['protocolName']] == 'tcp_ip':
        continue
    else:
        List.pop(i)
for flow in List:
    hm.add(flow)# Add each found tcp flow into the HM List
    l.append(flow[dic['source']] + flow[dic['destination']])
    cc += 1
count = 0

#print("Number of Flows: ", len(List), " Number of Flows Added: ", count)

def packet_values(pkt):#Read packet by packet from pcap and compare values
    global hm
    num_in_list_1 = 0
    if 'IP' not in pkt:
        return True
    if 'TCP' not in pkt:
        return True
    key = pkt['IP'].src + pkt['IP'].dst

    hm.addPacket(pkt)

    total = 0
    return True


f = scapy.sniff(offline="testbed-13jun.pcap", prn=packet_values, store=0)#Reads in packets line by line from passed in pcap file

