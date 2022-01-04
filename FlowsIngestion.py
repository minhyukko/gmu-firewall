
class FlowTime:
    def __init__(self, t):
        self.day = int(t[8:10])
        self.hour = int(t[11:13])
        self.min = t[14:16]
        self.sec = t[17:19] 

    def __lt__(self, other)
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

class FlowNode:
    def __init__(self, source, destination, total_num_packets, source_num, destination_num, startDateTime, tag, key):
        self.source = source# Source IP Address
        self.destination = ''# Destination IP Address
        self.key = key
        self.total_num_packets = 0 # Total number of packets in each flow if zero go to next element in linked list
        self.source_num = 0# number of source packets (Source->Destination)
        self.destination_num = 0# number of destination packets (Destination->Source)
        self.startDateTime = FlowTime(startDateTime)
        self.packets = []# List of binary strings representing each packet
        self.tag = ''# Benign or Malicious attack type of tcp flow
        self.next = None

    def __repr__(self):
        return "Tag: "+str(self.tag)






size = 110513
#hash()
mainArr = [None] * 110513

class HashMap:
    def __init__(self, size, attack):
        self.size = size
        self.arr = [None] * self.size
        self.attack = attack

    def add(self, flow):
        key = flow[dic['source']] + flow[dic['destinaiton']]
        key = hash(key)
        if key < 0 :
            key *= -1
        tag = "Normal" if flow[dic['Tag']] == 'Normal' else self.attack
        fn = FlowNode(flow[dic['source']], flow[dic['destination']], int(flow[dic['totalDestinationBytes']]) + int(flow[dic['totalSourceBytes']]), int(flow[dic['totalSourceBytes']]), int(flow[dic['totalDestinationBytes']]), int(flow[dic['totalSourceBytes']]), flow[dic['startDateTime']], tag, key)
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

    def addPacket(self, pkt):
        source = pkt['TCP'].source
        destination = pkt['TCP'].destination
        key = source + destination 
        key = hash(key)
        pos = key % self.size


        key2 = destination + source
        key2 = hash(key2)
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




    def remove(self, pos):
        temp = None
        if self.arr[pos] == None:
            return False
        if self.arr[pos].next == None:
            temp = self.arr[pos].deepcopy()
            self.arr[pos] = None
        else:
            temp = self.arr[pos].deepcopy()
            self.arr[pos] = self.arr[pos].next



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
    break
    List.append(x)


for flow in List:

