
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
import time
import logging
#def setup_logging(filename):
#    try:
#        with open(filename,'w')as f:
#            f.write('Flows Log')
#    except FileNotFoundError:
#        print("The log directory doesn't exist")
#    logging.basicConfig(filename = filename,
#                       filemode = 'w', 
#                       encoding = 'utf-8', 
#                       format = "%(name)s - %(levelname)s - %(message)s")

class FlowNode:#Linked List Node used within hashmap
    def __init__(self, source, src_port, destination, dst_port, t):# Attributes in Node correspond to FLow attributes from the XML
        self.source = source# Source IP Address
        self.destination = destination# Destination IP Address
        self.src_port = src_port
        self.dst_port = dst_port

        self.key = hash(str(source) + str(src_port) + str(destination) + str(dst_port))
        self.key_inv = hash(str(source) + str(src_port) + str(destination) + str(dst_port))
        self.t = t
        ### Is this an array of tcp headers? I thought that we remove the payload of the packets to just retrieve the headers
        self.packets = []
        # So if there are two items that both fit the same hashmap slot what do we do?
        self.next = None

    def __repr__(self):#String representation of Node used for debugging
        return "Tag: " + str(self.tag)


class HashMap:#Hashmap that holds a linked list of FlowNodes at each index
    def __init__(self, capacity, load_factor, timeout_time, socket, log_file):
        self.size = 0# Size of hashmap
        self.arr = [None] * capacity# Create array that i
        self.count = 0#Current Number of completed flows used for json naming
        self.capacity = capacity
        self.load_factor = load_factor
        self.timeout_time =  timeout_time
        self.socket = socket
        self.log_file = log_file
        setup_logging(log_file)
        print(log_file)
        logging.debug("Logging Setup")

    def addf(self, key, flow):#Add new node to the hashmap
        ### pkt cannot be used here, substituting this new flow creation for the passed flow
        key = hash(str(flow.source)+ str(flow.src_port)+str(flow.destination)+str(flow.dst_port))
             #str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        i1 = hash(key) % self.capacity
        if self.arr[i1] == None:
            ### pkt cannot be used here, substituting this new flow creation for the passed flow
            self.arr[i1] = flow
            #FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            #for i in range(len(flow.packets)):
                #self.arr[i1].packets.append(flow.packets[i])#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            return
        else:
            temp = self.arr[i1]
            #print(59)
            while (not(temp == None)):
                if temp.next == None:
                    temp.next = flow
                    ### Do we need to append the payload line here?
                    self.count += 1
                    return
                temp = temp.next

        ### May need to rehash here, need to make sure a inf loop doesn't happen
        
        return
    
    def add(self, pkt):
        src = pkt['IP'].src
        dst = pkt['IP'].dst
        dport = pkt['TCP'].dport
        sport = pkt['TCP'].sport
        FIN = pkt['TCP'].flags.F
        b_pkt = pkt_to_bin(pkt)
        logging.info("Packet Add, count {}".format(self.count))
        key = hash(str(src) + str(sport)+ str(dst) + str(dport))
        key_inv = hash(str(dst) + str(dport)+ str(src) + str(sport))
        i1 = hash(key) % self.capacity
        i2 = hash(key_inv) % self.capacity
        new_hash = self
        isfound = False
        ### There can be a situation where i1 is not present but i2 is
        ### we are creating flows for every direciton of traffic with this
        
        ### We look to see if either key or key_inv is present. If neither is, create flow pased off of key
        if self.arr[i1] == None and self.arr[i2]==None:
            self.arr[i1] = FlowNode(src, sport, dst, dport, time.time())
            self.arr[i1].packets.append(b_pkt)#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            isfound = True
        ### This section adds the packet to the proper location in the hm
        ### If either is present, add the packet to the present flow
        elif not(self.arr[i1] == None) and self.arr[i2] == None:
            ### Search through the present hm slot and if there is no match to our packet info create a flow in the empty hm slot
            temp = self.arr[i1]
            isfound = False
            while True:
                if temp.key == key:
                    temp.t = time.time()
                    temp.packets.append(b_pkt)
                    #self.count+=1
                    isfound= True
                if(temp.next==None):
                    break
                temp = temp.next
            if(not isfound):
                self.arr[i2] = FlowNode(src, sport, dst, dport, time.time())
                self.arr[i2].packets.append(b_pkt)
                self.count +=1

        elif self.arr[i1] == None and not(self.arr[i2] ==  None):
            ### Add the packet to self.arr[2]
            temp = self.arr[i2]
            isfound = False
            while True:
                if temp.key == key:
                    temp.t = time.time()
                    temp.packets.append(b_pkt)
                    #self.count+=1
                    isfound= True
                if(temp.next==None):
                    break
                temp = temp.next
            if(not isfound):
                self.arr[i1] = FlowNode(src, sport, dst, dport, time.time())
                self.arr[i1].packets.append(b_pkt)
                self.count +=1

        elif not(self.arr[i1] == None) and not(self.arr[i2] == None):            
            ### Actually, there can be flows that are in the same hm slot
            ### So we actually want to search the slot if its full for a match to our src/dst ip/ports if there is none in either then add to 1
            temp = self.arr[i2]
            isfound = False
            while True:
                if temp.key == key:
                    temp.t = time.time()
                    temp.packets.append(b_pkt)
                    #self.count+=1
                    isfound= True
                if(temp.next==None):
                    break
                temp = temp.next
            if(not isfound):
                temp = self.arr[i1]
                isfound = False
                while True:
                    if temp.key == key:
                        temp.t = time.time()
                        temp.packets.append(b_pkt)
                        #self.count+=1
                        isfound= True
                    if(temp.next==None):
                        break
                    temp = temp.next
            if(not isfound):
                ### Both hm slots have entries but none of them match the socket we are looking for, add to 1
                temp.next=FlowNode(src, sport, dst, dport, time.time())
                temp = temp.next
                temp.t = time.time()
                temp.packets.append(b_pkt)
                self.count +=1
                isfound=True
        if isfound and (FIN):
            self.remove(key)
        
        if (self.count/self.capacity) > self.load_factor:
            new_hash = self.rehash()
        return new_hash

    def remove(self, key):#Removes a flow and saves the flow in json format
        ### A key is passed, no key is needed
        logging.info("Remove: {}".format(self.count))
        #key = str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        i1 = hash(key) % self.capacity
        temp = self.arr[i1]
        prev = temp
        while True:
            print(temp.key)
            if temp.key == key:
                prev.next = temp.next
#                logging.info("Sending Flow to server {}".format(socket)) 
                #Sends the messages to the Server in the order expected(-> size, <- confirmation, -> data)
                d = {'pkt':temp.packets, 'src':temp.source, 'dst':temp.destination, 'sport':temp.src_port, 'dport':temp.dst_port}
                data = json.dumps(d)
                data = data.encode(encoding = 'UTF-8')
                #print(type(data))
                data2 = sys.getsizeof(data)
                #print(data2)
                self.socket.sendall(bytes(str(data2),encoding = 'utf8'))
                r = self.socket.recv(sys.getsizeof(int()))
                self.socket.sendall(data)

                
                
                return
            if(temp.next==None):
                break
            prev = temp
            temp = temp.next
        self.count-=1

    def rehash(self):
        ###Should this instantiation be all the same filed as the current HashMap (except for capacity)?
        new_hash  = HashMap(self.capacity * 2, self.load_factor, self.timeout_time, self.socket,self.log_file)
        old_capacity = self.capacity        
        for x in self.arr:
            temp = x
                  #self.arr[i]
            #print(148)
            while (not (temp == None)):
                t2 = temp
                t2.next = None
                new_hash.addf(temp.key,t2)
                temp = temp.next
        logging.info("Rehash\n From: {} To:{} ".format(old_capacity, new_hash.capacity))
        return new_hash

    def check_timeouts(self, t):
        for x in self.arr:
            temp = self.arr[i]
            print(160)
            while (not (temp == None)):
                if self.timeout_time > t - temp.time:
                    self.remove(temp.key)
                temp = temp.next
        self = new_hash
        return

    def __repr__(self):#String representation of hashmap used for testing
        ans = ""
        for i in range(len(self.arr)):
            if self.arr[i] == None:
                continue
            else:
                temp = self.arr[i]
                ans += "[" + str(i) + "]Head>"
                #print(177)
                while(not (temp == None)):
                    ans += " > "
                    ### This function was calling for startDateTime, I swapped to src and dst ports
                    ans += temp.source +":"+str(temp.src_port)+ " " + temp.destination + ":"+str(temp.dst_port)
                    temp = temp.next
            ans += "\n"
        return ans
def pkt_to_bin(pkt):
    line_length = 0
    file_num = 0
    image_arr = []
    i = 0
    t_pkt = pkt

    if pkt.haslayer("IP"):
        if pkt.haslayer("TCP"):
            t_pkt.remove_payload()
        elif pkt.haslayer("UDP"):
            t_pkt.remove_payload()
        else:
            t_pkt.remove_payload()
    pkt_hex=compat.bytes_hex(t_pkt)
    pkt_bin = bin (int.from_bytes(pkt_hex, byteorder= sys.byteorder))
    pkt_final = pkt_bin[2:]
    return pkt_final

def setup_logging(filename):
    logging.basicConfig(filename = filename, 
                        filemode = 'w', 
                        encoding = 'utf-8', 
                        level = logging.DEBUG, 
                        format = '%(name)s - %(levelname)s - %(message)s')

#hm = HashMap(100, 0.75, 25) # Recommended initial settings 100 Initial Capacity, 0.75 load factor, and a 25 second timeout time

#Using hashmap to store incoming flows will result in packet drops due to processing time.
#This is just unfortunate not much we can do in terms of performance I believe this has high efficiency
