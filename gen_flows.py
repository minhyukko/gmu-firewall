
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


class FlowNode:#Linked List Node used within hashmap
    def __init__(self, source, src_port, destination, dst_port, t):# Attributes in Node correspond to FLow attributes from the XML
        self.source = source# Source IP Address
        self.destination = destination# Destination IP Address
        self.src_port = src_port
        self.dst_port = dst_port

        self.key = hash(str(source) + str(src_port) + str(destination) + str(dst_port))
        self.key_inv = hash(str(source) + str(src_port) + str(destination) + str(dst_port))
        self.t = t
        self.packets = []
        self.next = None

    def __repr__(self):#String representation of Node used for debugging
        return "Tag: " + str(self.tag)


class HashMap:#Hashmap that holds a linked list of FlowNodes at each index
    def __init__(self, capacity, load_factor, timeout_time, socket):
        self.size = 0# Size of hashmap
        self.arr = [None] * capacity# Create array that i
        self.count = 0#Current Number of completed flows used for json naming
        self.capacity = capacity
        self.load_factor = load_factor
        self.timeout_time =  timeout_time
        self.socket = socket

    def addf(self, key, flow):#Add new node to the hashmap
        print("Flow Add",self.count)
        ### pkt cannot be used here, substituting this new flow creation for the passed flow
        key = str(flow.source)+ str(flow.src_port)+str(flow.destination)+str(flow.dst_port)
             #str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        i1 = hash(key) % self.capacity
        if self.arr[i1] == None:
            ### pkt cannot be used here, substituting this new flow creation for the passed flow
            self.arr[i1] = flow
                          #FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            self.arr[i1].packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            return
        else:
            temp = self.arr[i1]
            #print(59)
            while (not(temp == None)):
                if temp.next == None:
                    temp.next = flow
                    self.count += 1
                    return
                temp = temp.next
        
        return
    
    def add(self, pkt):
        print("Packet Add",self.count)
        key = str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        key_inv = str(pkt['IP'].dst) + str(pkt['TCP'].dport)+ str(pkt['IP'].src) + str(pkt['TCP'].sport)
        i1 = hash(key) % self.capacity
        i2 = hash(key_inv) % self.capacity

        is_found = False
        ### There can be a situation where i1 is not present but i2 is
        ### we are creating flows for every direciton of traffic with this
        if self.arr[i1] == None:
            self.arr[i1] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            self.arr[i1].packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            is_found = True
        else:
            temp = self.arr[i1]
            #print(84)
            while (not(temp == None)):
                if temp.key == key or temp.key == key_inv:
                    temp.t = time.time()
                    temp.packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
                    is_found = True
                temp = temp.next


        if self.arr[i2] == None and not is_found:
            self.arr[i2] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            self.arr[i2].packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            is_found = True
        elif not is_found:
            temp = self.arr[i2]
            #print(100)
            while (not(temp == None)):
                if temp.key == key or temp.key == key_inv:
                    temp.t = time.time()
                    temp.packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
                    is_found = True
                temp = temp.next

        if is_found and (0x01 & pkt['TCP'].flags):
            self.remove(key)

        
        if is_found == False:
            self.addf(key,FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time()))

        if (self.count/self.capacity) > self.load_factor:
            self.rehash()
            print(self.capacity)
        print(type(pkt['TCP'].flags&0x01),pkt['TCP'].flags&0x01)
        if is_found and (pkt['TCP'].flags.F):
            print('here')
            self.remove(key_inv)
        return

    def remove(self, key):#Removes a flow and saves the flow in json format
        ### A key is passed, no key is needed
        #key = str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        i1 = hash(key) % self.capacity
        temp = self.arr[i2]
        prev = temp
        print(126)
        while (not(temp == None)):
            if temp.key == key:
                prev.next = temp.next
                print("Send Single Flow") 
                #Sends the messages to the Server in the order expected(-> size, <- confirmation, -> data)
                d = {'packets':temp.packets, 'source':temp.source, 'destination':temp.destination}
                data = json.dumps(d)
                data2 = sys.getsizeof(data)
                print(data2)
                self.socket.sendall(bytes(str(data2)),'utf8')
                r = self.socket.recv(sys.getsizeof(int()))
                self.socket.sendall(bytes(data), 'utf8')


                return 
            prev = temp
            temp = temp.next

    def rehash(self):
        ###Should this instantiation be all the same filed as the current HashMap (except for capacity)?
        new_hash  = HashMap(self.capacity * 2, self.load_factor, self.timeout_time, self.socket)
        print("Rehash from:", self.capacity, "\nTo:",new_hash.capacity)
        
        for x in self.arr:
            temp = x
                  #self.arr[i]
            #print(148)
            while (not (temp == None)):
                t2 = temp
                t2.next = None
                new_hash.addf(temp.key,t2)
                temp = temp.next
        self = new_hash
        print(self.capacity)
        return

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


#hm = HashMap(100, 0.75, 25) # Recommended initial settings 100 Initial Capacity, 0.75 load factor, and a 25 second timeout time

#Using hashmap to store incoming flows will result in packet drops due to processing time.
#This is just unfortunate not much we can do in terms of performance I believe this has high efficiency
