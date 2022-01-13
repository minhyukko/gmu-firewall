
import json
import scapy.all as scapy
from xml.etree import ElementTree

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
    flow_dic['name'] = 'Flow_' + str(count) + '_attack_' + attack + ".json"
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
        source = pkt['TCP'].source
        destination = pkt['TCP'].destination
        key = source + destination 
        key = hash(key)
        if key < 0:
            key *= -1
        pos = key % self.size


        key2 = destination + source
        key2 = hash(key2)
        if key2 < 0:
            key2 *= -1
        pos2 = key2 % self.size

        one = self.arr[pos]
        if not one.key == key:
            while(not one.next == None):
                if one.next.key == key:
                    one = one.next
                    break
                one = one.next
        two = self.arr[pos]
        if not two.key == key:
            while(not two.next == None):
                if two.next.key == key:
                    two = two.next
                    break
                two = two.next
        if one.startDateTime < two.startDateTime: 
            add = one
        else:
            add = two
        add.arr.append(pkt)# Append Bits


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
print(List[0:4])

hm = HashMap(110513, "Infiltrating_Transfer")

#print(List)
l = []
cc = 0
for flow in List:
    #print("Here")
    if cc == 6:
        break
    hm.add(flow)
    l.append(flow[dic['source']] + flow[dic['destination']])
    print("Source: ", flow[dic['source']], "Destination: ",flow[dic['destination']] )
    #print(l[-1])
    cc += 1
print(l)
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




