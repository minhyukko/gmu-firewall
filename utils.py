"""
Utility functions.
"""

import torch
import torch.optim as optim
from torchvision import transforms
import numpy as np
import json
import os
import shutil

"""
Constants
"""
DATA_DIR = "data/"
TRAIN_DIR = os.path.join(DATA_DIR, "train")
TEST_DIR = os.path.join(DATA_DIR, "test")
DEV_DIR = os.path.join(DATA_DIR, "dev")
MODEL_DIR = "model/"
INPUT_DIM = 224

def preprocess_rt(pckts):
	"""
	Preprocesses packets for input to the model during real-time execution.
	It transforms the packet array from a string array with INPUT_DIM elements,
	each with length INPUT_DIM into a (3, INPUT_DIM, INPUT_DIM) binary torch tensor.

	:param pckts: (list(str)) -> the packet array

	:return: (torch.tensor(3, INPUT_DIM, INPUT_DIM)) -> the packets in the form of a binary torch tensor
	"""

	# truncate or bottom-pad packet array
	if len(pckts) > INPUT_DIM:
		pckts = pckts[0:INPUT_DIM]
	else:
		pckts += ["0"*(INPUT_DIM)]*(INPUT_DIM - len(pckts))

	# truncate or right-pad each packet
	if len(pckts[0]) > INPUT_DIM:
		pckts = [p[0:INPUT_DIM] for p in pckts]
	else:
		pckts = [p + ("0"*(INPUT_DIM - len(p))) for p in pckts]

	pckts = numerize_packets(pckts)
	
	return pckts

def numerize_packets(pckts):
	"""
	Transforms packet representation from list<str> -> binary tensor (3, INPUT_DIM, INPUT_DIM) and normalizes distribution.

	:param pckts: (array(str)) -> (222,) array of strings each of length 222

	:return: (torch.tensor) -> binary tensor 
	"""

	pckts = np.array([bin_to_list(p) for p in pckts])
	filler = np.zeros((INPUT_DIM, INPUT_DIM))
	pckts = np.stack([pckts, filler, filler])
	pckts = torch.tensor(pckts, dtype=torch.float32)
	normalize_func = transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
	pckts = normalize_func(pckts)

	return pckts

def preprocess_train(fname):
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
	Preprocesses the data; currently only modifies packet arrays to be of shape (INPUT_DIM,).
	Writes the output to data/data_preproc.json.
	
	:param fname: (str) -> the filename

	:return: None
	"""

	print("preprocessing data...")

	fpath = os.path.join(DATA_DIR, fname) # data/[fname].json
	with open(fpath) as infile:
		data = json.load(infile)
	
	# normalize train packet arrays to (INPUT_DIM,) dimensions
	train_data = data["train"]
	for datum in train_data:
		pckts = datum["packets"]
		
		# truncate or bottom-pad packet array
		if len(pckts) > INPUT_DIM:
			pckts = pckts[0:INPUT_DIM]
		else:
			pckts += ["0"*(INPUT_DIM)]*(INPUT_DIM - len(pckts))
		
		# truncate or right-pad each packet
		if len(pckts[0]) > INPUT_DIM:
			pckts = [p[0:INPUT_DIM] for p in pckts]
		else:
			pckts = [p + ("0"*(INPUT_DIM - len(p))) for p in pckts]

		# apply changes
		datum["packets"] = pckts
	
	data["train"] = train_data

	# normalize test packet arrays to (INPUT_DIM,) dimensions
	test_data = data["test"]
	for datum in test_data:
		pckts = datum["packets"]
		
		# truncate or bottom-pad packet array
		if len(pckts) > INPUT_DIM:
			pckts = pckts[0:INPUT_DIM]
		else:
			pckts += ["0"*(INPUT_DIM)]*(INPUT_DIM - len(pckts))
		
		# truncate or right-pad each packet
		if len(pckts[0]) > INPUT_DIM:
			pckts = [p[0:INPUT_DIM] for p in pckts]
		else:
			pckts = [p + ("0"*(INPUT_DIM - len(p))) for p in pckts]
		
		# apply changes
		datum["packets"] = pckts
	
	data["test"] = test_data

	# normalize dev packet arrays to (INPUT_DIM,) dimensions
	dev_data = data["dev"]
	for datum in dev_data:
		pckts = datum["packets"]
		
		# truncate or bottom-pad packet array
		if len(pckts) > INPUT_DIM:
			pckts = pckts[0:INPUT_DIM]
		else:
			pckts += ["0"*(INPUT_DIM)]*(INPUT_DIM - len(pckts))
		
		# truncate or right-pad each packet
		if len(pckts[0]) > INPUT_DIM:
			pckts = [p[0:INPUT_DIM] for p in pckts]
		else:
			pckts = [p + ("0"*(INPUT_DIM - len(p))) for p in pckts]
		
		# apply changes
		datum["packets"] = pckts
	
	data["dev"] = dev_data

	preproc_fpath = os.path.join(DATA_DIR, "data_preproc.json")
	with open(preproc_fpath, "w") as outfile:
		json.dump(data, outfile, indent=4)

def check_training(fname):
	"""
	Checks if the training file has been properly preprocessed.

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
		if num_packets != INPUT_DIM or size_packets != INPUT_DIM:
			preprocessed = False
			print("[Train] Flow " + str(i) + " is not normalized")
			print("shape=" + str((num_packets, size_packets)))

	test_data = data["test"]
	for i, datum in enumerate(test_data):
		pckts = datum["packets"]
		num_packets = len(pckts)
		size_packets = len(pckts[0])
		if num_packets != INPUT_DIM or size_packets != INPUT_DIM:
			preprocessed = False
			print("[Test] Flow " + str(i) + " is not normalized")
			print("shape=" + str((num_packets, size_packets)))

	dev_data = data["dev"]
	for i, datum in enumerate(dev_data):
		pckts = datum["packets"]
		num_packets = len(pckts)
		size_packets = len(pckts[0])
		if num_packets != INPUT_DIM or size_packets != INPUT_DIM:
			preprocessed = False
			print("[Test] Flow " + str(i) + " is not normalized")
			print("shape=" + str((num_packets, size_packets)))

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

	# write test meta
	test_meta = {"length": len(test_data), "size": test_size}
	with open(os.path.join(TEST_DIR, "test_meta.json"), "w") as outfile:
		json.dump(test_meta, outfile, indent=4)


	# split dev portion
	dev_data = data["dev"]
	for i in range(0,len(dev_data),dev_size):
		segment = {}
		segment["dev"] = test_data[i:min(i+dev_size, len(dev_data))]
		mod_fname = "dev_" + str(int(i/dev_size)) + ".json"
		segment_fpath = os.path.join(DEV_DIR, mod_fname) # data/dev/dev_i.json
		with open(segment_fpath, "w") as outfile:
			json.dump(segment, outfile, indent=4)

	# write dev meta
	dev_meta = {"length": len(dev_data), "size": dev_size}
	with open(os.path.join(DEV_DIR, "dev_meta.json"), "w") as outfile:
		json.dump(dev_meta, outfile, indent=4)

def get_meta(mode):
	"""
	Retrieves meta-data for specified dataset (train, test, dev).

	:param mode: (str) -> the mode

	:return: (int) -> total number of elements
			 (int) -> the maximum number of elements in a given file
	"""

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

def save_ckpt(ckpt, is_best):
	"""
	Saves checkpoint.

	:param ckpt: (dict) -> a dictionary storing the state of a model
	:param is_best: (bool) -> enables special storage of the best model

	:return: None
	"""

	ckpt_fpath = os.path.join(MODEL_DIR, "ckpt.pt")
	torch.save(ckpt, ckpt_fpath)
	if is_best:
		best_fpath = os.path.join(MODEL_DIR, "model.pt")
		shutil.copyfile(ckpt_fpath, best_fpath)

def load_ckpt(ckpt_fname, model=None, optimizer=None):
	"""
	Loads checkpoint.

	:param ckpt_fname: (str) -> the checkpoint filename
	:param model: (torch.nn) -> the neural network
	:param optimizer: (torch.optim) -> the optimizer

	:return: None
	"""

	ckpt_fpath = os.path.join(MODEL_DIR, ckpt_fname)
	ckpt = torch.load(ckpt_fpath)
	if model != None:
		model.load_state_dict(ckpt["model_state_dict"], strict=False)
	if optimizer != None:
		optimizer.load_state_dict(ckpt["optimizer_state_dict"])
	
	epoch = ckpt["epoch"]

	return model, optimizer, epoch

def create_ckpt(model, optimizer, epoch=0):
	
	# store model state
	ckpt = {
		"model_state_dict": model.state_dict(),
		"optimizer_state_dict": optimizer.state_dict(),
		"epoch": epoch + 1
	}

	return ckpt

def compute_accuracy(inferences, ground_truth):
	"""
	Compute accuracy of model predictions.

	:param inferences: (torch.tensor) -> list of classifications
	:param ground_truth: (torch.tensor) -> list of ground truth values

	:return: (float) -> accuracy
	"""

	diff_map = [1 if inf == g_t else 0 for inf, g_t in zip(inferences, ground_truth)]
	accuracy = sum(diff_map) / len(diff_map)

	return accuracy


def bin_to_list(bin):
	"""
	Given a binary sequence stored a string, "b_0b_1b_2...b_n" returns a list
	where each element is a bit b_i.

	:param bin: (str) -> the binary sequence

	:return: (list) -> a list of ints
	"""

	return [int(b) for b in bin]
