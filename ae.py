"""
TODO:
- get src/dest IP
- add other types of attacks to tag_to_ix (if needed)
- implement IPC (run will be communicating directly with socket)
- add stopping condition based on validation 
- decide whether or not to use transfer learning
"""

import torch
import torch.nn as nn
import torchvision.models as models
import torch.optim as optim
from torch.utils.data import Dataset
from torch.utils.data import DataLoader
import numpy as np
import json
import os

"""
Constants
"""
DATA_DIR = "data/"
PCKT_DIM = 224

"""
Set model device
"""
device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using {device} device")

"""
Set model hyperparameters
"""
torch.manual_seed(42)
BATCH_SIZE = 64
SHUFFLE = True
NUM_WORKERS = 6
MAX_EPOCHS = 100

"""
The following classes and functions are concerned with data ingestion.
"""

class NetworkFlowDataset(Dataset):
	def __init__(self, fname):
		"""
		pass data_fpath=train.json if train or test.json if test
		"""
		self.fname = os.path.join(DATA_DIR, fname)
		self.transform = transform

		def __len__(self):
			"""
			Returns the number of elements in the dataset

			:return: (int) -> the dataset length
			"""

			return len(self.flows)

		def __getitem__(self, idx):
			"""
			Gets the requested item from JSON data file.
			The JSON has the following nested structure:
			{
				"Training" OR "Testing": [
					{
						"packets" = [p_0, ....., p_n] where each p_i is a bit string
						"Tag": "t"
					}

					{
						packets = [p_0, ....., p_n] where each p_i is a bit string
						"Tag": "t"
					}
					.
					.
					.
				         ]

			}
			It is a single object consisting of an array of objects composed of (packet, tag) pairs.			

			:param idx: (int) -> the index

			:return: (pckts, tag) -> returns the binary packet representation and its corresponding tag; tag=None on test dataset
			"""

			# read data
			with open(self.fname, "r") as infile:
				data = json.load(infile)
			data = data[self.fname.split("/")[1].split(".")[0]]
			datum = data[idx]
			pckts = datum["packets"]
			pckts = np.asarray([bin_to_list(p) for p in pckts])
			# normalize pckts
			if len(pckts) > PCKT_DIM:
				pckts = pckts[0:MAX_PCKTS+1]
			elif len(pckts) < PCKT_DIM:
				pckts = np.pad(pckts, ((0, PCKT_DIM - len(pckts)), (0,0)), mode="constant", constant_values=(0,))
			pckts = torch.from_numpy(pckts)

			# represent tag as one-hot vectors
			tags_to_ix = {"Normal": 0, "Infiltrating_Transfer": 1}
			if "train" in self.fname:
				ix = tags_to_ix[datum["Tag"]]
				tag = [0 for i in range(len(tags_to_ix))]
				tag[ix] = 1
				tag = torch.tensor(tag)
			else:
				tag = None

			return pckts, tag

def _bin_to_list(bin):
	"""
	Given a binary sequence stored a string, "b_0b_1b_2...b_n" returns a list
	where each element is a bit b_i. The resulting list is projected from [0,1]
	range to [0,255]. 

	:param bin: (str) -> the binary sequence

	:return: (list) -> a list of ints
	"""

	return [int(b)*255 for b in bin]


"""
The following classes and functions are concered with model training and inference.
"""

class NetworkFlow():
	"""
	A network flow.
	"""
	def __init__(self, pckts, src_ip, dest_ip, src_port, dest_port):
		"""
		Initializes a network flow.

		:param pckts: (np.ndarray) -> array of packets where each packet is represented as a binary string (shape=(222,222))
		:param src_ip: (str) -> the source ip
		:param dest_ip: (str) -> the destination ip
		:param src_port: (str) -> the source port
		:param dest_port: (str) -> the destination port
		"""

		self.pckts = pckts
		self.src_ip = src_ip
		self.dest_ip = dest_ip
		self.src_port = src_port
		self.dest_port = dest_port


def save_checkpoint(checkpoint, is_best, checkpoint_fpath, best_model_fpath):
    """
	Saves checkpoint
	:param checkpoint: (dict) -> a dictionary storing the state of a model
	:param is_best: (bool) -> enables special storage of the best model
	:param checkpoint_dir: (str) -> the target directory for the checkpoint
	:param best_model_dir: (str) -> the target directory for the model
    """

    torch.save(checkpoint, checkpoint_fpath)
    if is_best:
        shutil.copyfile(checkpoint_fpath, best_model_fpath)


def load_checkpoint(checkpoint_fpath, model, optimizer):
	
	checkpoint = torch.load(checkpoint_fpath)
	model.load_state_dict(checkpoint["model_state_dict"], strict=False)
	optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
	return model, optimizer, checkpoint["epoch"]

def load_checkpoint(checkpoint_fpath, model, optimizer):
	
	checkpoint = torch.load(checkpoint_fpath)
	model.load_state_dict(checkpoint["model_state_dict"], strict=False)
	optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
	return model, optimizer, checkpoint["epoch"]

class Model():
	def __init__(self):
		self.model = models.DenseNet(pretrained=False)
		f_conv_layer = [nn.Conv2d(1, 3, kernel_size=3, stride=1, padding=1, dilation=1, groups=1, bias=True)]
		f_conv_layer.extend(list(self.model.features))
		self.model.features = nn.Sequential(*f_conv_layer)

def train(model, optimizer, data_fname):
	"""
	Trains the model and saves it.

	:param model: (torch.nn) -> the model
	:param optimizer: (torch.optim) -> the optimizer
	:param epochs: number of epochs
	:param training_data: ()
	"""

	# load data
	train_params = {"batch_size": BATCH_SIZE,
					"shuffle": SHUFFLE,
					"num_workers": NUM_WORKERS
				   }
	
	train_data = Dataset(data_fname)
	train_loader = DataLoader(train_data, **params)

	# train model
	model.train()
	loss_function = nn.NLLLoss()
	for epoch in range(MAX_EPOCHS):
		print(f"Starting epoch {epoch}...")
		for flow_batch, tags in train_loader:
			# clean gradient memory, setup hardware
			model.zero_grad()
			flow_batch, tags = flow_batch.to(device), tags.to(device)
			
			# forward prop
			tag_scores = model(flow_batch)
			
			# backprop
			loss = loss_function(tag_scores, tags)
			loss.backward()
			optimizer.step()

	# Save model
	model = {
		"epoch": epoch + 1,
		"model_state_dict": model.state_dict(),
		"optimizer_state_dict": optimizer.state_dict()
	}
	torch.save(model, "model/model.pt")

def infer(model, data_fname):
	"""
	This function cannot be written without figuring out IPC
	"""
# 	model.eval()

# 	# load data
# 	train_params = {"batch_size": BATCH_SIZE,
# 					"shuffle": SHUFFLE,
# 					"num_workers": NUM_WORKERS
# 				   }
# 	test_data = Dataset(data_fname)
# 	test_loader = DataLoader(test_data, **params)

# 	ix_to_tags = {0: "Normal", 1: "Infiltrating_Transfer"}
# 	# perform inference
# 	inferences = []
# 	with torch.no_grad():
# 		for flow_batch, tags in test_loader:
# 			flow_batch = flow_batch.to(device)
# 			tag_scores = model(flow_batch).numpy()
# 			output = [np.argmax(t_s) for t_s in tag_scores]
# 			flows.append((flow_batch, output))

#	# The model will only enter eval() mode during testing, otherwise its always in training mode
#	model.train()
	
	pass


"""
The following functions are concerned with the AE-firewall IPC interface.
"""
"""
The grammar for AE-firewall communications can be described like this:
Vocabulary: actions, target_types, targets
- actions: the set of all the possible things the firewall can do : {b, p, d} // block, pass, deny
- target_types: the set of all possible types of targets : {sip, sport} // source IP, source port
- targets: the set of all numbers of some fixed length, it is the actual numerical identifier of the type of target 
  (e.g. if target_type=src IP, then target would be the actual address) : {0,9}^n

A rule can be stored in a dictionary and, in general, looks like this: <action: a, target_type: t, target: T, sip (optional): sip>
We might want to propose multiple rules at once so we can store these tuples in a list. We can call a list of rules a rule set.
An rule set in its general form looks like this: [rule_0,...,rule_n] 

Note: when proposing a rule that blocks the source port, also include the source IP in the rule

e.g. if the firewall should block the source IP 192.168.13.14 and destination port 80, the rule_set would look like:
[
	{
		action: b,
		target_type: sip,
		target: 192.168.13.14,
		sip: None
	}

	{
		action: b,
		target_type: sport,
		target: 80,
		sip: 192.168.13.14
	}
]
"""

def generate_rules(attack, flow):
	"""
	Generate rules based on the attack type and the metadata contained in flow.

	:param attack: (str) -> the type of attack (e.g. DOS)
	:param flow: (NetworkFlow) -> NetworkFlow object

	:return: (list(tuples)) -> a rule set
	"""

	rule_set = []
	
	if attack == "dos":
		rule_set.append( {"action": "b", "target_type":"sip", "target": flow.src_ip} )
		rule_set.append( {"action": "b", "target_type":"sport", "target": flow.src_port} )
	elif attack == "infiltrating_transfer":
		pass

	return rule_set

def transmit_rule(rules):
	"""
	Transmit proposed rules to the firewall in JSON format. 

	:param rules: (list(tuples)) -> the proposed rules

	:return: (bool) -> transmission outcome
	"""

	pass






















