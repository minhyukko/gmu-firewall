"""
Trains the neural model. 
"""

import utils
import numpy as np
import json
import shutil
import os
import torch
import torch.nn as nn
import torchvision.models as models
from torchvision import transforms
import torch.optim as optim
from torch.utils.data import Dataset
from torch.utils.data import DataLoader

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
Model device.
"""
device = "cuda" if torch.cuda.is_available() else "cpu"

"""
Model hyperparameters.
"""
torch.manual_seed(42)
BATCH_SIZE = 32
SHUFFLE = True
NUM_WORKERS = 4
MAX_EPOCHS = 10
PATIENCE = 7


class NetworkFlowDataset(Dataset):
	"""
	Manages dataset-model delivery during training, validation, and testing.
	"""

	def __init__(self, mode):
		"""
		Initializes the Dataset.

		:param mode: (str) -> the data mode {"train", "test", "dev"}
		"""

		self.mode = mode
		self.length, self.size = utils.get_meta(mode)
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

		# get packets 
		idx = idx % self.size
		datum = data[idx]
		pckts = datum["packets"]
		# transform packet representation from list<str> -> binary tensor (3, PCKT_DIM, PCKT_DIM)
		pckts = np.array([utils.bin_to_list(p) for p in pckts]) 
		filler = np.zeros((PCKT_DIM, PCKT_DIM))
		pckts = np.stack([pckts, filler, filler])
		pckts = torch.tensor(pckts, dtype=torch.float32)
		# normalize
		normalize_func = transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
		pckts = normalize_func(pckts)

		# get tag
		tag = None
		if self.mode == "train" or self.mode == "dev":
			tag = self.tags_to_ix[datum["Tag"]]

		return pckts, tag

def train(model, optimizer, loss):
	"""
	Trains the model, performs validation at the end of every epoch, saves best model.

	:return: None
	"""

	print("training model...")

	model.train()

	# load data
	params = {"batch_size": BATCH_SIZE,
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
	batch_i = 0
	while train == True and epoch < MAX_EPOCHS:
		print(f"starting epoch {epoch}...")
		for flows, tags in train_loader:
			print(f"processing batch {batch_i}...")
			# clean gradient memory, setup hardware
			model.zero_grad()
			flows, tags = flows.to(device), tags.to(device)
			
			# forward prop
			tag_scores = model(flows)
			
			# backprop
			loss = loss(tag_scores, tags)
			loss.backward()
			optimizer.step()

			batch_i += 1

		# store model state
		ckpt = {
			"epoch": epoch + 1,
			"model_state_dict": .model.state_dict(),
			"optimizer_state_dict": optimizer.state_dict()
		}
		# validate
		accuracy = validate(model)
		print("Accuracy on validation set: " + str(accuracy))
		# save checkpoint
		utils.save_ckpt(ckpt, is_best)
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

	:return: None
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
		for flows, tags in dev_loader:
			flows, tags = flows.to(device), tags.to(device)
			tag_scores = model(flows).numpy()
			inferences += [np.argmax(t_s) for t_s in tag_scores]
			ground_truth += [np.argmax(t) for t in tags]

	accuracy = utils.compute_accuracy(inferences, ground_truth)

	# model will always be in train mode unless its running inference ops
	model.train()

	return accuracy


def main():
	"""
	Drives the program.
	"""
	
	num_classes = 5
	model = models.densenet121(pretrained=True)
	model.classifier = nn.Sequential(nn.Linear(in_features=1024, out_features=num_classes), nn.Softmax(dim=1))
	optimizer = optim.Adam(model.parameters(), lr=0.1)
	loss = nn.NLLLoss()

	model = train(model, optimizer, loss)


if __name__ == "__main__":
	main()





















