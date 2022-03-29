
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
    def __init__(self, capacity, load_factor, timeout_time):
        self.size = size# Size of hashmap
        self.arr = [None] * capacity# Create array that i
        self.count = 0#Current Number of completed flows used for json naming
        self.capacity = capacity
        self.load_factor = load_factor
        self.timeout_time =  timeout_time


    def add(self, key, flow):#Add new node to the hashmap
        key = str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        i1 = hash(key) % self.capacity
        if self.arr[i1] == None:
            self.arr[i1] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            self.arr[i1].packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            return
        else:
            temp = self.arr[i1]
            while (not(temp == None)):
                if temp.next = None:
                    temp.next = flow
                    self.count += 1
                    return
        return

    def add(self, pkt):
        key = str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        key_inv = str(pkt['IP'].dst) + str(pkt['TCP'].dport)+ str(pkt['IP'].src) + str(pkt['TCP'].sport)
        i1 = hash(key) % self.capacity
        i2 = hash(key_inv) % self.capacity

        is_found = False

        if self.arr[i1] == None:
            self.arr[i1] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            self.arr[i1].packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            is_found = True
        else:
            temp = self.arr[i1]
            while (not(temp == None)):
                if temp.key == key or temp.key == key_inv:
                    temp.t = time.time()
                    temp.packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
                    is_found = True



        if self.arr[i2] == None and not is_found:
            self.arr[i2] = FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time())
            self.arr[i2].packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
            self.count += 1
            is_found = True
        elif and not is_found:
            temp = self.arr[i2]
            while (not(temp == None)):
                if temp.key == key or temp.key == key_inv:
                    temp.t = time.time()
                    temp.packets.append("Payload Line")#Add payload to FlowNode - Replace Payload Line
                    is_found = True

        if is_found and (0x01 & pkt['TCP'].flags):
            self.remove(key)

        
        if is_found == False:
            self.add(FlowNode(pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport, time.time()))

        if (self.count/self.capacity) > self.load_factor:
            rehash()

        iif is_found and (0x01 & pkt['TCP'].flags):
            self.remove(key_inv)

        return

    def remove(self, key):#Removes a flow and saves the flow in json format
        key = str(pkt['IP'].src) + str(pkt['TCP'].sport)+ str(pkt['IP'].dst) + str(pkt['TCP'].dport)
        i1 = hash(key) % self.capacity
        temp = self.arr[i2]
        prev = temp
            while (not(temp == None)):
                if temp.key == key
                    prev.next = temp.next
                    #send_pkt(temp.packets, temp.source, temp.src_port, temp.destination, temp.dst_port) - Needs to be added
                    return
                prev = temp
                temp = temp.next

    def rehash(self):
        new_hash  = HashMap(self.capacity * 2, 0.75)
        for x in self.arr:
            temp = self.arr[i]
            
            while (not (temp == None)):
                t2 = temp
                t2.next = None
                new_hash.add(t2)
                temp = temp.next
        self = new_hash
        return

    def check_timeouts(self, t):
        for x in self.arr:
            temp = self.arr[i]
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
                while(not (temp == None)):
                    ans += " > "
                    ans += temp.source + " " + temp.destination + " " + str(temp.startDateTime)
                    temp = temp.next
            ans += "\n"
        return ans


hm = HashMap(100, 0.75, 25) # Recommended initial settings 100 Initial Capacity, 0.75 load factor, and a 25 second timeout time

#Using hashmap to store incoming flows will result in packet drops due to processing time.
#This is just unfortunate not much we can do in terms of performance I believe this has high efficiency