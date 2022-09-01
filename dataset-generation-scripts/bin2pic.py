import pandas as pd
import time
import os
import numpy as np
from PIL import Image as im

data_path = "../Data/pe-machine-learning-dataset/samples/"
output_path = "Data/test/"


filenames = os.listdir(data_path)
#filenames = filenames[:5]
start_time = time.time()

width_table =[(10, 32), (30, 64), (60, 128), (100, 256), (200, 384), (500, 512), (1000, 768), (1001, 1024)]

try:
	os.stat(output_path)
except:
	os.makedirs(output_path)

for df in (filenames):
	filepath = data_path+df
	#print(filepath)
	try:
		file = open(filepath, "rb")
	except:
		continue
	filesize = int(round(os.stat(filepath).st_size/1024))

	image_width = 1
	for width in width_table:
		if width[0] < filesize:
			image_width = width[1]

	byte = file.read(1)
	byte_array = []
	image_array = []
	while byte:
		byte = int.from_bytes(byte, byteorder='little', signed=False)
		if len(byte_array) < image_width:
			byte_array.append(byte)
		else:
			image_array.append(byte_array)
			byte_array = []
		if not isinstance(byte, int):
			print(byte)

		byte = file.read(1)

	while len(byte_array) < image_width:
		byte_array.append(0)

	image_array.append(byte_array)

	np_array = np.array(image_array)

	data = im.fromarray((np_array * 255).astype(np.uint8))

	data_name = df+".png"
	datapath = output_path + data_name
	try:
		data.save(datapath)
	except:
		continue

print("--- Runtime of program is %s seconds ---" % (time.time() - start_time))
