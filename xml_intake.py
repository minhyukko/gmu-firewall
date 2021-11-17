import os
import scapy.all as scapy
from xml.etree import ElementTree

name = 'TestbedSatJun12Flows.xml'
d = ElementTree.parse(name)
inputs = d.findall('TestbedSatJun12')


vals = ['appName', 'totalSourceBytes', 'totalDestinationBytes', 'totalDestinationPackets','totalSourcePackets', 'sourcePayloadAsBase64','sourcePayloadAsUTF','direction','sourceTCPFlagsDescription', 'source','protocolName', 'sourcePort', 'destination','destinationPort','startDateTime','stopDateTime','Tag']
d = {}


for x in range(len(vals)):
	d[vals[x]] = x
#print(d)
List = []


for f in inputs:
	x = []
	for y in vals:
		x.append(f.find(y).text)
	#print(x)
	List.append(x)

print(List[0])

f = scapy.rdpcap('testbed-12jun.pcap')

print("Length of pcap file: ", len(f), "Length of data info: ", len(List))
pck = f[0]
print("Type of packet: ",(type(pck)))
print(line)

pck.show()

