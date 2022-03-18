"""
TODO:
- get src/dest IP
- implement IPC (run will be communicating directly with socket)
- add stopping condition based on validation
- decide whether or not to use transfer learning
- use checksum
- perform val split
- DUMMY AE
- decide attack |-> response dictionary
- set firewall to default state
(save firewall configuration)
"""

import torch
import torch.nn as nn
import torchvision.models as models
from torchvision import transforms
import torch.optim as optim
from torch.utils.data import Dataset
from torch.utils.data import DataLoader
import numpy as np
import json
from collections import defaultdict
import os

"""
Constants
"""
DATA_DIR = "data/"
TRAIN_DIR = os.path.join(DATA_DIR, "train")
TEST_DIR = os.path.join(DATA_DIR, "test")
DEV_DIR = os.path.join(DATA_DIR, "dev")
MODEL_DIR = "model/"
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
NUM_WORKERS = 2
MAX_EPOCHS = 100
PATIENCE = 7


"""
The following classes and functions are concerned with data ingestion.
"""

def preprocess_data(fname):
	"""
	The passed file is assumed to be in JSON format and to have this structure:
	{
		"train": [
			{
				"packets": [p_0, ....., p_n] where each p_i is a bit string
				"Tag": t
			}
			.
			.
			.
		]

		"test": [
			{
				"packets": [p_0, ....., p_n] where each p_i is a bit string
				"Tag": t
			}
			.
			.
			.
		]

		"dev": [
			{
				"packets": [p_0, ....., p_n] where each p_i is a bit string
				"Tag": t
			}
			.
			.
			.
		]
	}
	It is a dictionary where each key points to a list of {"packets": [packets], Tag:[tag]} dictionaries.
	Preprocesses the data so it is in order; currently only modifies packet arrays to be of shape (PCKT_DIM, PCKT_DIM).
	Writes the output to data/data_preproc.json.

	:return: None
	"""

	print("preprocessing data...")

	fpath = os.path.join(DATA_DIR, fname) # data/[fname].json
	with open(fpath) as infile:
		data = json.load(infile)
	
	# normalize train packet arrays to (PCKT_DIM, PCKT_DIM) dimensions
	train_data = data["train"]
	for datum in train_data:
		pckts = datum["packets"]
		
		# truncate or bottom-pad packet array
		
		
		if len(pckts) > PCKT_DIM:
			pckts = pckts[0:PCKT_DIM]
		else:
			pckts += ["0"*(PCKT_DIM)]*(PCKT_DIM - len(pckts))
		
		# truncate or right-pad each packet
		if len(pckts[0]) > PCKT_DIM:
			pckts = [p[0:PCKT_DIM] for p in pckts]
		else:
			pckts = [p + ("0"*(PCKT_DIM - len(p))) for p in pckts]


		
		# apply changes
		datum["packets"] = pckts
	
	data["train"] = train_data

	# normalize test packet arrays to (PCKT_DIM, PCKT_DIM) dimensions
	test_data = data["test"]
	for datum in test_data:
		pckts = datum["packets"]
		
		# truncate or bottom-pad packet array
		if len(pckts) > PCKT_DIM:
			pckts = pckts[0:PCKT_DIM]
		else:
			pckts += ["0"*(PCKT_DIM)]*(PCKT_DIM - len(pckts))
		
		# truncate or right-pad each packet
		if len(pckts[0]) > PCKT_DIM:
			pckts = [p[0:PCKT_DIM] for p in pckts]
		else:
			pckts = [p + ("0"*(PCKT_DIM - len(p))) for p in pckts]
		
		# apply changes
		datum["packets"] = pckts
	
	data["test"] = test_data

	preproc_fpath = os.path.join(DATA_DIR, "data_preproc.json")
	with open(preproc_fpath, "w") as outfile:
		json.dump(data, outfile, indent=4)

	# normalize test packet arrays to (PCKT_DIM, PCKT_DIM) dimensions
	# dev_data = data["dev"]
	# for datum in dev_data:
	# 	pckts = datum["packets"]
		
	# 	# truncate or bottom-pad packet array
	# 	if len(pckts) > PCKT_DIM:
	# 		pckts = pckts[0:PCKT_DIM]
	# 	else:
	# 		pckts += ["0"*(PCKT_DIM)]*(PCKT_DIM - len(pckts))
		
	# 	# truncate or right-pad each packet
	# 	if len(pckts[0]) > PCKT_DIM:
	# 		pckts = [p[0:PCKT_DIM] for p in pckts]
	# 	else:
	# 		pckts = [p + ("0"*(PCKT_DIM - len(p))) for p in pckts]
		
	# 	# apply changes
	# 	datum["packets"] = pckts
	
	# data["dev"] = dev_data


def check_preprocess(fname):
	"""
	Checks if the data file has been properly preprocessed.

	:param fname: (str) -> the filename of the preprocessed dataset

	:return: (bool) -> indicates whether or not preprocessing went well
	"""
	
	print("verifying data is preprocessed...")
	
	preprocessed = True

	preproc_fpath = os.path.join(DATA_DIR, fname)
	with open(preproc_fpath) as infile:
		data = json.load(infile)

	train_data = data["train"]
	for i, datum in enumerate(train_data):
		pckts = datum["packets"]
		num_packets = len(pckts)
		size_packets = len(pckts[0])
		if num_packets != PCKT_DIM or size_packets != PCKT_DIM:
			preprocessed = False
			print("[Train] Flow " + str(i) + " is not normalized")
			print("shape=" + str((num_packets, size_packets)))

	test_data = data["test"]
	for i, datum in enumerate(test_data):
		pckts = datum["packets"]
		num_packets = len(pckts)
		size_packets = len(pckts[0])
		if num_packets != PCKT_DIM or size_packets != PCKT_DIM:
			preprocessed = False
			print("[Test] Flow " + str(i) + " is not normalized")
			print("shape=" + str((num_packets, size_packets)))

	# dev_data = data["dev"]
	# for i, datum in enumerate(dev_data):
	# 	pckts = datum["packets"]
	# 	num_packets = len(pckts)
	# 	size_packets = len(pckts[0])
	# 	if num_packets != PCKT_DIM or size_packets != PCKT_DIM:
	# 		preprocessed = False
	# 		print("[Test] Flow " + str(i) + " is not normalized")
	#		print("shape=" + str((num_packets, size_packets)))

	return preprocessed

def split_data(fname, train_size, test_size, dev_size):
	"""
	The passed file is assumed to be in JSON format and to have this structure:
	{
		"train": [
			{
				"packets": [p_0, ....., p_n] where each p_i is a bit string
				"Tag": t
			}
			.
			.
			.
		]

		"test": [
			{
				"packets": [p_0, ....., p_n] where each p_i is a bit string
				"Tag": t
			}
			.
			.
			.
		]

		"dev": [
			{
				"packets": [p_0, ....., p_n] where each p_i is a bit string
				"Tag": t
			}
			.
			.
			.
		]
	}
	It is a dictionary where each key points to a list of {"packets": [packets], Tag:[tag]} dictionaries.
	Splits the data file into a set of training and testing files, each containing a specified number of instances.
	Writes these files along with a corresponding JSON meta-file with the following structure:
	{
    	"length": (int),
    	"size": (int)
	}
	where "length" records the total number of elements in the set and "size" records the max number of instances in each file

	:param fname: (str) -> the filename of the data
						   the filename must be either: train.json, test.json, or dev.json
	:param train_size: (int) -> the number of instances in each train file
	:param test_size: (int) -> the number of instances in each test file

	:return: None
	"""

	print("splitting data...")

	fpath = os.path.join(DATA_DIR, fname) # data/[fname].json
	with open(fpath) as infile:
		data = json.load(infile)

	# split train portion
	train_data = data["train"]
	train_length = 0
	for i in range(0,len(train_data), train_size):
		segment = {}
		segment["train"] = train_data[i:min(i+train_size, len(train_data))]
		mod_fname = "train_" + str(int(i/train_size)) + ".json"
		segment_fpath = os.path.join(TRAIN_DIR, mod_fname) # data/train/train_i.json
		with open(segment_fpath, "w") as outfile:
			json.dump(segment, outfile, indent=4)
	
	# write train meta
	train_meta = {"length": len(train_data), "size": train_size}
	with open(os.path.join(TRAIN_DIR, "train_meta.json"), "w") as outfile:
		json.dump(train_meta, outfile, indent=4)

	# split test portion
	test_data = data["test"]
	for i in range(0,len(test_data),test_size):
		segment = {}
		segment["test"] = test_data[i:min(i+test_size, len(test_data))]
		mod_fname = "test_" + str(int(i/test_size)) + ".json"
		segment_fpath = os.path.join(TEST_DIR, mod_fname) # data/test/test_i.json
		with open(segment_fpath, "w") as outfile:
			json.dump(segment, outfile, indent=4)

	test_meta = {"length": len(test_data), "size": test_size}
	with open(os.path.join(TEST_DIR, "test_meta.json"), "w") as outfile:
		json.dump(test_meta, outfile, indent=4)


	# split dev portion
	# dev_data = data["dev"]
	# for i in range(0,len(dev_data),dev_size):
	# 	segment = {}
	# 	segment["dev"] = test_data[i:min(i+dev_size, len(dev_data))]
	# 	mod_fname = "dev_" + str(int(i/dev_size)) + ".json"
	# 	segment_fpath = os.path.join(DEV_DIR, mod_fname) # data/dev/dev_i.json
	# 	with open(segment_fpath, "w") as outfile:
	# 		json.dump(segment, outfile, indent=4)

	# dev_meta = {"length": len(dev_data), "size": dev_size}
	# with open(os.path.join(DEV_DIR, "dev_meta.json"), "w") as outfile:
	# 	json.dump(dev_meta, outfile, indent=4)

def get_meta(mode):

	meta_fpath = None
	if mode == "train":
		meta_fpath = os.path.join(TRAIN_DIR, "train_meta.json")
	elif mode == "test":
		meta_fpath = os.path.join(TEST_DIR, "test_meta.json")
	elif mode == "dev":
		meta_fpath = os.path.join(DEV_DIR, "dev_meta.json")
	else:
		print("Error: unsupported model")
		quit()

	with open(meta_fpath) as infile:
		data = json.load(infile)

	length = data["length"]
	size = data["size"]

	return length, size



class NetworkFlowDataset(Dataset):
	"""

	"""

	def __init__(self, mode):
		"""
		Initializes the Dataset.

		:param mode: (str) -> the data mode {"train", "test", "dev"}
		"""

		self.mode = mode
		self.length, self.size = get_meta(mode)
		# represent tag as one-hot vectors
		# self.tags_to_ix = {"Normal": 0,
		# 			  	   "Infiltrating_Transfer": 1, 
		# 			       "Bruteforce_SSH": 2, 
		# 			       "DDoS": 3,
		# 			       "HTTP_DDoS": 4
		# 			       }
		self.tags_to_ix = {"Normal": 0,
						   "Infiltrating_Transfer": 1}			   
		# self.ix_to_tags = {0: "Normal",
		# 			  	     1: "Infiltrating_Transfer", 
		# 			         2: "Bruteforce_SSH", 
		# 			         3: "DDoS",
		# 			         4: "HTTP_DDoS"
		# 			       }
		self.ix_to_tags = {0: "Normal",
						   1: "Infiltrating_Transfer"}

	def __len__(self):
		"""
		Returns the length of the dataset

		:return: (int) -> the dataset length
		"""

		return self.length

	def __getitem__(self, idx):
		"""
		Gets the requested item from JSON data file.
		The JSON has the following nested structure:
		{
			"train" or "test" or "dev": [
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
		It is a dictionary where each key points to a list of {"packets": [packets], Tag:[tag]} dictionaries.			

		:param idx: (int) -> the index

		:return: (pckts, tag) -> returns the binary packet representation and its corresponding tag; tag=None on test dataset
		"""

		# read data
		fpath = None
		if self.mode == "train":
			fname = "train_" + str(int(idx/self.size)) + ".json"
			fpath = os.path.join(TRAIN_DIR, fname)
		elif self.mode == "test":
			fname = "train_" + str(int(idx/self.size)) + ".json"
			fpath = os.path.join(TEST_DIR, fname)
		elif self.mode == "dev":
			fname = "dev_" + str(int(idx/self.size)) + ".json"
			fpath = os.path.join(DEV_DIR, fname)		

		with open(fpath) as infile:
			data = json.load(infile)[self.mode]

		idx = idx % self.size
		datum = data[idx]
		pckts = datum["packets"]
		pckts = torch.tensor([bin_to_list(p) for p in pckts])


		tag = None
		if self.mode == "train" or self.mode == "dev":
			ix = self.tags_to_ix[datum["Tag"]]
			tag = np.zeros(len(self.tags_to_ix))
			tag[ix] = 1
			tag = torch.tensor(tag)

		print(type(pckts))
		print(pckts.shape)

		return pckts, tag

def bin_to_list(bin):
	"""
	Given a binary sequence stored a string, "b_0b_1b_2...b_n" returns a list
	where each element is a bit b_i.

	:param bin: (str) -> the binary sequence

	:return: (list) -> a list of ints
	"""

	return [int(b) for b in bin]

"""
The following classes and functions are concered with model training and inference.
"""

def save_ckpt(ckpt, is_best):
	"""
	Saves ckpt
	:param ckpt: (dict) -> a dictionary storing the state of a model
	:param is_best: (bool) -> enables special storage of the best model
	"""

	ckpt_fpath = os.path.join(MODEL_DIR, "ckpt.pt")
	torch.save(ckpt, ckpt_fpath)
	if is_best:
		best_fpath = os.path.join(MODEL_DIR, "model.pt")
		shutil.copyfile(ckpt_fpath, best_fpath)

def load_ckpt(ckpt_fname, model, optimizer):
	
	ckpt_fpath = os.path.join(MODEL_DIR, ckpt_fname)
	ckpt = torch.load(ckpt_fpath)
	model.load_state_dict(ckpt["model_state_dict"], strict=False)
	optimizer.load_state_dict(ckpt["optimizer_state_dict"])
	return model, optimizer, ckpt["epoch"]

class AnalyticEngine():
	"""
	The model takes the form of a pretrained DenseNet CNN. Given the marked differences between ImageNet
	and our dataset, the parameters of the convolutional layers of the network will be modified along
	with those of the linear layers (fine-tuning).
	"""

	def __init__(self, num_classes, pretrained=True):
		"""
		Initializes the model.

		:param num_classes: (int) -> the number of classes
		:param pretrained: (bool) -> whether or not to load pretrained model
		"""

		self.model = models.densenet161(pretrained=pretrained)
		
		# transform flows from (224,224) to (3,224,244) with conv layer
		f_conv_layer = [nn.Conv2d(1, 3, kernel_size=3, stride=1, padding=1, dilation=1, groups=1, bias=True)]
		f_conv_layer.extend(list(self.model.features))
		self.model.features = nn.Sequential(*f_conv_layer)
		
		# append custom linear layer
		self.model.classifier = nn.Linear(in_features=1024, out_features=num_classes)

	def get_model(self):
		return self.model

def train(model, optimizer, train_fname, val_fname, ckpt_fname):
	"""
	Trains the model and saves it.

	:param model: (torch.nn) -> the model
	:param optimizer: (torch.optim) -> the optimizer
	:param train_fname: (str) -> the training data filename
	:param val_fname: (str) -> the validation data filename
	:param ckpt_fname: (str) -> the ckpt filename

	:return: (torch.nn) -> the trained model 
	"""

	model.train()
	loss_function = nn.NLLLoss()

	# load data
	train_params = {"batch_size": BATCH_SIZE,
					"shuffle": SHUFFLE,
					"num_workers": NUM_WORKERS
				   }
	
	train_data = NetworkFlowDataset(mode="train")
	train_loader = DataLoader(train_data, **params)

	# train model
	trespasses = 0
	patience = PATIENCE
	best_accuracy = 0
	is_best = True
	train = True
	epoch = 0
	while train == True:
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

		# store model state
		ckpt = {
			"epoch": epoch + 1,
			"model_state_dict": model.state_dict(),
			"optimizer_state_dict": optimizer.state_dict()
		}
		# validate
		accuracy = validate(model=model, data_fname=val_fname)
		print("Accuracy on validation set: " + str(accuracy))
		# save checkpoint
		save_ckpt(ckpt, is_best)
		epoch += 1
		# model is improving
		if accuracy > best_accuracy:
			best_accuracy = accuracy
			trespasses = 0
			is_best = True
		# running out of patience...
		else:
			trespasses += 1
			# model is definitely overfitting
			if trespasses == patience:
				# get best model and quit
				model, optimizer, epoch = load_ckpt("model.pt", model, optimizer)
				train = False
			is_best = False

	return model

def validate(model):
	"""
	Validates model on development set and computes accuracy.

	:param model: (torch.nn) -> the neural network
	"""

	print("validating model...")

	model.eval()

	# load data
	params = {"batch_size": BATCH_SIZE,
					"shuffle": SHUFFLE,
					"num_workers": NUM_WORKERS
				   }
	dev_data = NetworkFlowDataset(mode="dev")
	dev_loader = DataLoader(dev_data, **params)

	# perform inference
	inferences = []
	ground_truth = []
	with torch.no_grad():
		for flow_batch, tags in dev_loader:
			flow_batch = flow_batch.to(device), tags.to(device)
			tag_scores = model(flow_batch).numpy()
			# inferences += [np.argmax(t_s) for t_s in tag_scores]
			print("Tag scores info:")
			print(tag_scores)
			print(type(tag_scores))
			print(type(tag_scores[0]))
			print()
			print("Tags info:")
			print(tags)
			print(type(tags))
			print(type(tags[0]))
			quit()
			

	accuracy = compute_accuracy(inferences, ground_truth)

	# model will always be in train mode unless its running inference ops
	model.train()

	return accuracy

def compute_accuracy(inferences, ground_truth):
	"""
	Compute accuracy of model predictions.

	:param classifications: (list(int)) -> list of classifications
	:param ground_truth: (list(int)) -> list of ground truth values

	:return: (float) -> accuracy
	"""

	diff_map = [1 if inf == g_t else 0 for inf, g_t in zip(inferences, ground_truth)]
	accuracy = sum(diff_map) / len(diff_map)

	return accuracy


def main():
	"""
	Drives the program.
	"""

	ae = AnalyticEngine(num_classes=2, pretrained=True).get_model()
	validate(ae)

if __name__ == "__main__":
	main()



























