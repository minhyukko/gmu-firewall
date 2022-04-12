
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
        ### Is this an array of tcp headers? I thought that we remove the payload of the packets to just retrieve the headers
        self.packets = []
        # So if there are two items that both fit the same hashmap slot what do we do?
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
        ### pkt cannot be used here, substituting this new flow creation for the passed flow
        key = hash(str(flow.source)+ str(flow.src_port)+str(flow.destination)+str(flow.dst_port))
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
                    ### Do we need to append the payload line here?
                    self.count += 1
                    return
                temp = temp.next

        ### May need to rehash here, need to make sure a inf loop doesn't happen
        
        return
    
    def add(self, pkt):
        print("Packet Add",self.count)
        key = hash(str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport))
        key_inv = hash(str(pkt['IP'].dst) + str(pkt['TCP'].dport)+ str(pkt['IP'].src) + str(pkt['TCP'].sport))
        i1 = hash(key) % self.capacity
        i2 = hash(key_inv) % self.capacity
        new_hash = self
        isfound = False
        ### There can be a situation where i1 is not present but i2 is
        ### we are creating flows for every direciton of traffic with this
        
        ### We look to see if either key or key_inv is present. If neither is, create flow pased off of key
        if self.arr[i1] == None and self.arr[i2]==None:
            self.arr[i1] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            self.arr[i1].packets.append(pkt['TCP'])#Add payload to FlowNode - Replace Payload Line
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
                    temp.packets.append(pkt)
                    #self.count+=1
                    isfound= True
                if(temp.next==None):
                    break
                temp = temp.next
            if(not isfound):
                self.arr[i2] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
                self.arr[i2].packets.append(pkt['TCP'])
                self.count +=1

        elif self.arr[i1] == None and not(self.arr[i2] ==  None):
            ### Add the packet to self.arr[2]
            temp = self.arr[i2]
            isfound = False
            while True:
                if temp.key == key:
                    temp.t = time.time()
                    temp.packets.append(pkt['TCP'])
                    #self.count+=1
                    isfound= True
                if(temp.next==None):
                    break
                temp = temp.next
            if(not isfound):
                self.arr[i1] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
                self.arr[i1].packets.append(pkt['TCP'])
                self.count +=1

        elif not(self.arr[i1] == None) and not(self.arr[i2] == None):            
            ### Actually, there can be flows that are in the same hm slot
            ### So we actually want to search the slot if its full for a match to our src/dst ip/ports if there is none in either then add to 1
            temp = self.arr[i2]
            isfound = False
            while True:
                if temp.key == key:
                    temp.t = time.time()
                    temp.packets.append(pkt['TCP'])
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
                        temp.packets.append(pkt['TCP'])
                        #self.count+=1
                        isfound= True
                    if(temp.next==None):
                        break
                    temp = temp.next
            if(not isfound):
                ### Both hm slots have entries but none of them match the socket we are looking for, add to 1
                temp.next=FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
                temp = temp.next
                temp.t = time.time()
                temp.packets.append(pkt['TCP'])
                self.count +=1
                isfound=True
        if isfound and (pkt['TCP'].flags.F):
            self.remove(key)
        
        if (self.count/self.capacity) > self.load_factor:
            print(self.capacity)
            new_hash = self.rehash()
            print(type(new_hash)) 
            print(self.capacity)
        return new_hash

    def remove(self, key):#Removes a flow and saves the flow in json format
        ### A key is passed, no key is needed
        print("Remove-----------------------------------------")
        #key = str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        i1 = hash(key) % self.capacity
        temp = self.arr[i1]
        prev = temp
        print(key, self.arr[i1].key)
        while True:
            print(temp.key)
            if temp.key == key:
                prev.next = temp.next
                print("Send Single Flow") 
                print(temp.packets[0].summary())
                #Sends the messages to the Server in the order expected(-> size, <- confirmation, -> data)
                d = {'packets':temp.packets, 'source':temp.source, 'destination':temp.destination}
                data = json.dumps(d)
                data = data.encode(encoding = 'UTF-8')
                data2 = sys.getsizeof(data)
                print(data2)
                self.socket.sendall(bytes(str(data2)),'utf8')
                r = self.socket.recv(sys.getsizeof(int()))
                self.socket.sendall(bytes(data), 'utf8')
                
                
                return
            if(temp.next==None):
                print('End')
                break
            prev = temp
            temp = temp.next
        self.count-=1

    def rehash(self):
        ###Should this instantiation be all the same filed as the current HashMap (except for capacity)?
        new_hash  = HashMap(self.capacity * 2, self.load_factor, self.timeout_time, self.socket)
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
        print("Rehash\n From: {} To:{} ".format(old_capacity, new_hash.capacity))
        print(type(new_hash))
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


#hm = HashMap(100, 0.75, 25) # Recommended initial settings 100 Initial Capacity, 0.75 load factor, and a 25 second timeout time

#Using hashmap to store incoming flows will result in packet drops due to processing time.
#This is just unfortunate not much we can do in terms of performance I believe this has high efficiency
