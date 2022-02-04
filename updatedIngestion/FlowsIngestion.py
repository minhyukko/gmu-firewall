
import os
import json
import scapy.all as scapy
from xml.etree import ElementTree
import binascii
import socket
import math
import datetime
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
        self.min = int(t[14:16])
        self.sec = int(t[17:19])
    def __eq__(self, other):
        if self.day == other.day and self.hour == other.hour and self.min == other.min and self.sec == other.sec:
            return True
        else:
            return False

    def __lt__(self, other): # Allows for less than comparisons to be used within FlowTime Object
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
    def __gt__(self, other): # Allows for less than comparisons to be used within FlowTime Object
        if self.day == other.day:
            if self.hour == other.hour:
                if self.min  == other.min:
                    if self.sec > other.sec:
                        return True
                    else:
                        return False
                elif self.sec > other.sec:
                    return True
                else:
                    return False

            elif self.hour > other.hour:
                return True
            else:
                return False
        elif self.day > other.day:

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
    def __init__(self, source, destination, total_num_packets, source_num, destination_num, startDateTime, stopDateTime, tag, key):# Attributes in Node correspond to FLow attributes from the XML
        self.source = source# Source IP Address
        self.destination = destination# Destination IP Address
        self.key = key
        self.total_num_packets = total_num_packets # Total number of packets in each flow if zero go to next element in linked list
        self.source_num = source_num# number of source packets (Source->Destination)
        self.destination_num = destination_num# number of destination packets (Destination->Source)
        self.startDateTime = FlowTime(startDateTime)
        self.stopDateTime = FlowTime(stopDateTime)
        self.packets = []# List of binary strings representing each packet
        self.tag = tag# Benign or Malicious attack type of tcp flow
        self.next = None# The Next Node

    def __repr__(self):#String representation of Node used for debugging
        return "Tag: " + str(self.tag)

def pkt_to_bin(pkt):# Conversts packet into string binary representation which is then added to the Flow Object
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
    flow_dic['name'] = './Flows33/Flow_' + str(count) + '_attack_' + attack + ".json"
    #print("Writing JSON Name: ",flow_dic['name'])
    with open(flow_dic['name'], 'w') as f:
        json.dump(flow_dic, f)
        f.close()
    return


class HashMap:#Hashmap that holds a linked list of FlowNodes at each index
    def __init__(self, size, attack):
        self.entries = 0
        self.size = size# Size of hashmap
        self.arr = [None] * self.size# Create array that i
        self.attack = attack# Attack type for the days Flow
        self.count = 0#Current Number of completed flows used for json naming

    def add(self, flow):#Add new node to the hashmap
       # print("Adding")
        added = False
        key = flow[dic['source']] + flow[dic['destination']]
        key = hash(key)
        if key < 0 :
            key *= -1
        tag = "Normal" if flow[dic['Tag']] == 'Normal' else self.attack
        fn = FlowNode(flow[dic['source']], flow[dic['destination']], int(flow[dic['totalDestinationBytes']]) + int(flow[dic['totalSourceBytes']]), int(flow[dic['totalSourceBytes']]), int(flow[dic['totalDestinationBytes']]), flow[dic['startDateTime']], flow[dic['stopDateTime']], tag, key)
        pos = key % self.size

        if self.arr[pos] == None:
            self.arr[pos] = fn
            added = True
        else:
            node = self.arr[pos]
            while(not (node == None)):
                if(node.next == None):
                    node.next = fn
                    added = True
                    break
                node = node.next
        if added == False:
            print("Failed to Add Flow")


    def containsFlow(self, key):#Checks to see if a flow exists within the hm
        pos = key % self.size
        temp = self.arr[pos]
        global List

        if temp == None:
            #sys.exit()
            return False

        else:
            if temp.key == key:
                return True
            else:
                while not (temp == None):
                    if temp.key == key:
                        return True
                    temp = temp.next
        return False

    def getFlow(self, key):
        pos = key % self.size
        temp = self.arr[pos]
        if temp == None:
            print("Flow Not Found")
            return None
        else:
            if temp.key == key:
                return temp
            else:
                while not (temp == None):
                    if temp.key == key:
                        return temp
                    temp = temp.next
        return None
    def getFlows(self, key):
        ans = []
        pos = key % self.size
        temp = self.arr[pos]
        if temp == None:
            print("Flow Not Found")
            return []
        else:
            while not (temp == None):
                if temp.key == key:
                    ans.append(temp)
                temp = temp.next
        return ans
    def addPacket(self, pkt):#Adds a packet to the corresponding flow
        global l
        source = pkt['IP'].src
        destination = pkt['IP'].dst
        #print("%",source,"%",destination,"%")
        key = source + destination 
        #print("Key: ", key)
        key = hash(key)
       # print("Adding Packet Time")
       # print("Packet Time: ", pkt.time)
       # print("Final Packet Time")
        p_time = datetime.datetime.fromtimestamp(pkt.time)
        time = FlowTime(p_time.strftime('%Y-%m-%dT%H:%M:%S'))
        #print("Time Is: ", time.strftime('%Y-%m-%d %H:%M:%S'))

        add = None

        o = False
        t = False
        if key < 0:
            key *= -1
        key2 = destination + source
        key2 = hash(key2)
        if key2 < 0:
            key2 *= -1

        

        one = self.getFlows(key)
        two = self.getFlows(key2)
       # print("One Size: ",len(one))
       # print("Two Size: ",len(two))
        if ((len(one) > 0)) and ((len(two) > 0)):
            t1 = None
            t2 = None
            for x in one:
                if (x.startDateTime < time or x.startDateTime == time) and (time < x.stopDateTime or time == x.stopDateTime):
                    t1 = x
                    break
            for x in two:
                if (x.startDateTime < time or x.startDateTime == time) and (time < x.stopDateTime or time == x.stopDateTime):
                    t2 = x
                    break
            if not (t1 == None) and not (t2 == None):
                if t1.startDateTime < t2.startDateTime:
                    add = one 
                    add.source_num -= 1 
                    add.total_num_packets -= 1 
                else: 
                    add = two 
                    add.destination_num -= 1 
                    add.total_num_packets -= 1 
        elif ((len(one) > 0)):
            for x in one:
                if (x.startDateTime < time or x.startDateTime == time) and (time < x.stopDateTime or time == x.stopDateTime):
                    add = x
                    add.source_num -= 1 
                    add.total_num_packets -= 1 
                    break
        elif ((len(two) >0)):
            for x in two:
                if (x.startDateTime < time or x.startDateTime == time) and (time < x.stopDateTime or time == x.stopDateTime):
                    add = x
                    add.source_num -= 1 
                    add.total_num_packets -= 1 
                    break
        else:
            print("Packet Can't Find Home")
        '''if (not(one == None)) and (not(two == None)):# if both one and two have potential flows then pick the one with the smaller start tim
            if one.startDateTime < two.startDateTime:
                add = one
                add.source_num -= 1 #Decrement source and total number of packets
                add.total_num_packets -= 1
            else:
                add = two
                add.destination_num -= 1# Decrement destination and total number of packets
                add.total_num_packets -= 1

        elif (not(one == None)):#
            add = one

            add.source_num -= 1 # Decrement source and total number of packets
            add.total_num_packets -= 1

        elif (not(two == None)):
            add = two
            add.destination_num -= 1#Decrement destination and total number of packets
            add.total_num_packets -= 1'''


       # print("Add: ",add)

        if add == None:# If add is None here that means a packet was failed to be found
           # print(key, " or ", key2)
           # print("Failed")
            return
        add.packets.append(pkt_to_bin(pkt))# Append Bit representation of packet to flow node

        if add.total_num_packets == 0:# If the current flow is now zero meaning no additional space for new packets remove it from the hashmap
            self.remove(add.key)


    def remove(self, key):#Removes a flow and saves the flow in json format
        global List 
        cc = 0


        #sys.exit()
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

vals = ['appName', 'totalSourceBytes', 'totalDestinationBytes', 'totalDestinationPackets','totalSourcePackets', 'sourcePayloadAsBase64','sourcePayloadAsUTF','direction','sourceTCPFlagsDescription', 'source','protocolName', 'sourcePort', 'destination','destinationPort','startDateTime','stopDateTime','Tag']
dic = {}#Allows to get index from XML identifier using the identifier name
for i in range(len(vals)):
    dic[vals[i]] = i

List = []

for f in inputs:
    x = []
    for y in vals:
        x.append(f.find(y).text)
    List.append(x)

hm = HashMap(110513, "Infiltrating_Transfer")

l = []
cc = 0
for i in range(len(List)-1, -1, -1):
    if List[i][dic['protocolName']] == 'tcp_ip':
        continue
    else:
        List.pop(i)
for flow in List:
    hm.add(flow)
    l.append(flow[dic['source']] + flow[dic['destination']])
    cc += 1
count = 0
for i in hm.arr:
    if not (i == None):
        temp = i
        #count += 1
        while not (temp == None):
            temp = temp.next
            count += 1
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

f = scapy.sniff(offline="testbed-13jun.pcap", prn=packet_values, store=0)#Reads in 4 packets from pcap file passed in


