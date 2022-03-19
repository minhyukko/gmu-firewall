"""
The folllowing functions perform preprocessing and postprocessing
"""

import json
import os

"""
Constants
"""
DATA_DIR = "data/"
TRAIN_DIR = os.path.join(DATA_DIR, "train")
TEST_DIR = os.path.join(DATA_DIR, "test")
DEV_DIR = os.path.join(DATA_DIR, "dev")
PCKT_DIM = 224

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
	
	:param fname: (str) -> the filename

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



