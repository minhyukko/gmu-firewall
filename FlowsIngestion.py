class FlowNode:
    def __init__(self):
        self.source = ''# Source IP Address
        self.destination = ''# Destination IP Address
        self.total_num_packets = 0 # Total number of packets in each flow if zero go to next element in linked list
        self.source_num = 0# number of source packets (Source->Destination)
        self.destination_num = 0# number of destination packets (Destination->Source)
        self.packets = []# List of binary strings representing each packet
        self.tag = ''# Benign or Malicious attack type of tcp flow
        self.next = None

    def __repr__(self):
        return "Tag: "+str(self.tag)

class LinkedList:
    def __init__(self):
        self.head = None


l = LinkedList()
print(l.head)
l.head = FlowNode()
print(l.head.destination_num)
print(l.head)
l.head.tag = "Malicious"
print(l.head)

print(l.head.next)