import os
import scapy.all as scapy
from xml.etree import ElementTree
import json
import binascii
import json


packet_number = 0
num_in_list_1 = 0
num_in_list_2 = 0

name = 'TestbedSunJun13Flows.xml'
d = ElementTree.parse(name)
inputs = d.findall('TestbedSunJun13Flows')


vals = ['appName', 'totalSourceBytes', 'totalDestinationBytes', 'totalDestinationPackets','totalSourcePackets', 'sourcePayloadAsBase64','sourcePayloadAsUTF','direction','sourceTCPFlagsDescription', 'source','protocolName', 'sourcePort', 'destination','destinationPort','startDateTime','stopDateTime','Tag']
d = {}


for x in range(len(vals)):
	d[vals[x]] = x



List = []

for f in inputs:
	x = []
	for y in vals:
		x.append(f.find(y).text)
	List.append(x)

dic = {}#Allows to get index from XML identifier using the identifier name
for i in range(len(vals)):
	dic[vals[i]] = i


num_b = 0#Number of Benign Pakcets (TCP Only)
num_m = 0#Number of Malicious Packets (TCP Only)

num_m_all = 0 # Number of Benign Packets (Everything UDP, Ethernet, TCP, etc)
num_b_all = 0# Number of Benign Packets (Everything UDP, Ethernet, TCP, etc)

attack_list = []
normal_list = []
for i in List: # Loop Through Entire XML determine number of normal/attack packets add to appropriate list normal/attack
	if i[dic['protocolName']] == 'tcp_ip':
		if i[dic['Tag']] == 'Normal':
			num_b += 1
			normal_list.append(i)

		elif i[dic['Tag']] == 'Attack':
			num_m += 1
			attack_list.append(i)
	if i[dic['Tag']] == 'Normal':
		num_b_all += 1

	elif i[dic['Tag']] == 'Attack':
		num_m_all += 1
print("TCP ONLY")#Packets Lost
print("Number of Benign Packets: ", num_b)
print("Number of Malicious Packets: ", num_m)
print("Everything Included")
print("Number of Benign Packets: ", num_b_all)
print("Number of Malicious Packets: ", num_m_all)

def in_attack_xml(x):# finds if a packet(XML) is in attack list
	for i in attack_list:

		if str(x[d['source']]) == str(i[d['source']]) and str(x[d['destination']]) == str(i[d['destination']]):
			if x[d['destinationPort']] == 'netbios_ns':
				x[d['destinationPort']] = 137
			if x[d['sourcePort']] == 'netbios_ns':
				x[d['sourcePort']] = 137

			if i[d['destinationPort']] == 'netbios_ns':
				i[d['destinationPort']] = 137
			if i[d['sourcePort']] == 'netbios_ns':
				i[d['sourcePort']] = 137

			if str(x[d['destinationPort']]) == str(i[d['destinationPort']]) and str(x[d['sourcePort']]) == str(i[d['sourcePort']]):
				return True
	return False


def in_normal_xml(x):# Finds out if a packet(XML) is in normal
	for i in normal_list:
		if str(x[d['source']]) == str(i[d['source']]) and str(x[d['destination']]) == str(i[d['destination']]):
			if x[d['destinationPort']] == 'netbios_ns':
				x[d['destinationPort']] = 137
			if x[d['sourcePort']] == 'netbios_ns':
				x[d['sourcePort']] = 137

			if i[d['destinationPort']] == 'netbios_ns':
				i[d['destinationPort']] = 137
			if i[d['sourcePort']] == 'netbios_ns':
				i[d['sourcePort']] = 137

			if str(x[d['destinationPort']]) == str(i[d['destinationPort']]) and str(x[d['sourcePort']]) == str(i[d['sourcePort']]):
				return True
	return False

def in_attack_pcap(pkt):# finds if a packet(pcap) is in attack list(XML)
	for x in attack_list:
		if 'IP' in pkt:
			if 'TCP' in pkt:
				if str(pkt['IP'].src) == str(x[d['source']]) and str(pkt['IP'].dst) == str(x[d['destination']]):
					if pkt['TCP'].sport == 'netbios_ns':
						pkt['TCP'].sport = 137
					if pkt['TCP'].dport == 'netbios_ns':
						pkt['TCP'].dport = 137
					if str(x[d['destinationPort']]) == str(pkt['TCP'].dport) and str(x[d['sourcePort']]) == str(pkt['TCP'].sport):
						#Translate to Binary add to json
						print()
def in_normal_pcap(pkt):# finds if a packet(pcap) is in attack list(XML)
	for x in attack_list:
		if 'IP' in pkt:
			if 'TCP' in pkt:
				if str(pkt['IP'].src) == str(x[d['source']]) and str(pkt['IP'].dst) == str(x[d['destination']]):
					if pkt['TCP'].sport == 'netbios_ns':
						pkt['TCP'].sport = 137
					if pkt['TCP'].dport == 'netbios_ns':
						pkt['TCP'].dport = 137
					if str(x[d['destinationPort']]) == str(pkt['TCP'].dport) and str(x[d['sourcePort']]) == str(pkt['TCP'].sport):
						#Translate to Binary add to json
						print()



number_in_both = 0
for x in attack_list:
	if in_normal_xml(x):
		number_in_both += 1
print("Number of Attack Packets also in Normal List: ", number_in_both)



total = 0
def packet_values(pkt):#Read packet by packet from pcap and compare values
	global attacks
	global total
	num_in_list_1 = 0
	for x in List:
		if 'IP' in pkt:
			if 'TCP' in pkt:
				if str(pkt['IP'].src) == str(x[d['source']]) and str(pkt['IP'].dst) == str(x[d['destination']]):
					if pkt['TCP'].sport == 'netbios_ns':
						pkt['TCP'].sport = 137
					if pkt['TCP'].dport == 'netbios_ns':
						pkt['TCP'].dport = 137
					if str(x[d['destinationPort']]) == str(pkt['TCP'].dport) and str(x[d['sourcePort']]) == str(pkt['TCP'].sport):
						#Translate to Binary add to json
						print()
	print("Total Number of Copies: ", total)
	print("END")
	total = 0
	pkt.show()
	return True


print("Initial List Length: ", len(List))
for i in range(len(List)-1, -1, -1):
	if (List[i][d['Tag']] == "Normal"):
		List.pop(i)
print("Final List Length: ", len(List))


#f = scapy.sniff(offline="testbed-13jun.pcap", prn=packet_values, store=0, count = 4)#Reads in 4 packets from pcap file passed in


#with open("attacks.json", "w") as outfile:
#	json.dumps(dic, indent=4)

