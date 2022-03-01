import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

# Set device
device = 'cuda' if torch.cuda.is_available() else 'cpu'
print(f'Using {device} device')

# Hyperparameters
torch.manual_seed(42)


def segment_flows(pckts, min, max):
	"""
	Segments packet stream into flows of shape (222,222). A single packet
	takes up 222 bytes. Padding and truncation will be applied to normalize the
	data but only if the flow is composed of greater than :param min: packets and
	less than :param max: packets.

	:param pckts: (np.ndarray) -> the packet stream (each line represents a single packet)
	:param min: (int) -> minimum number of packets
	:param max: (int) -> maximum number of packets 

	:return: ([np.ndarray]) -> list of flows
	"""



class NeuralNetwork(nn.Module):
	def __init__(self):
	super(NeuralNetwork, self).__init__()
	self.flatten = nn.Flatten()
	self.linear_relu_stack = nn.Sequential(
	    nn.Linear(28*28, 512),
	    nn.ReLU(),
	    nn.Linear(512, 512),
	    nn.ReLU(),
	    nn.Linear(512, 10),
	)

	def forward(self, x):
		x = self.flatten(x)
		logits = self.linear_relu_stack(x)
		return logits


"""
The following functions feed the AE-firewall IPC interface. 

The grammar for AE-firewall communications can be described like this:
Vocabulary: actions, target_types, targets
- actions: the set of all the possible things the firewall can do : {bl}
- target_types: the set of all possible types of targets : {sip, dip, sport, dport}
- targets: the set of all numbers of some fixed length, it is the actual numerical identifier of the type of target 
  (e.g. if target_type=src IP, then target would be the actual address) : {0,9}^n

# the proposed rules can be stored as list of tuples, this allows arbitrary number of measures to be taken per flow
rules: [(action_0,target_type_0, target_0),..., (action_n, target_type_n, target_n)] 
e.g. if the firewall should block the source IP 192.168.13.14 and destination port 80, rules: [(bl, src_IP,  192.168.13.14), (bl, dest_port, 80)]
"""

def generate_rules(attack, flow_meta):
	"""
	Generate rules based on the attack type and the flow metadata.

	:param attack: (str) -> the type of attack (e.g. DOS)
	:param flow_meta: (dict) -> <K (str): network field (e.g. src IP, dest IP), V (str): identifier>

	:return: (list(tuples)) -> a list of tuples with the following 
	"""

	

def transmit_rule(rules):
	"""
	Transmit proposed rules to the firewall.

	:param rules: (list(tuples)) -> the proposed rules

	:return: (bool) -> transmission outcome
	"""





























