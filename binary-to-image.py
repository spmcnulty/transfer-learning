###########################
#
# author: Daniel Laden
# @ dthomasladen@gmail.com
#
###########################
#Take a directory of binaries and converts them to images similar to the malnet dataset

import numpy as np
from PIL import Image as im
import os
from os import walk

import time
start_time = time.time()

# file = open("pinentry-gnome3", "rb")
# width = 256

width_table =[(10, 32), (30, 64), (60, 128), (100, 256), (200, 384), (500, 512), (1000, 768), (1001, 1024)]

mypath = "..\\Data\\binaries\\"
print(mypath)
quit
directory = "..\\Data\\png\\"
print(directory)

try:
	os.stat(directory)
except:
	os.mkdir(directory)

f = []
for (dirpath, dirnames, filenames) in walk(mypath):
	f.extend(filenames) 
	break

for df in f:
	filepath = mypath+df
	#name, ext = os.path.splitext(filepath)
	print(filepath)
	try:
		file = open(filepath, "rb")
	except:
		continue
	filesize = int(round(os.stat(filepath).st_size/1024))
	print(filesize)

	image_width = 0
	for width in width_table:
		if width[0] < filesize:
			image_width = width[1]

	print(image_width)


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

	print(len(image_array))

	np_array = np.array(image_array)

	#print(np_array.shape)

	data = im.fromarray((np_array * 255).astype(np.uint8))

	data_name = df+"-img.png"
	data_path = directory + data_name
	try:
		data.save(data_path)
	except:
		continue

print("--- Runtime of program is %s seconds ---" % (time.time() - start_time))

#########################
#
# https://dl.acm.org/doi/pdf/10.1145/2016904.2016908
# https://www.kite.com/python/answers/how-to-read-bytes-from-a-binary-file-in-python
# https://stackoverflow.com/questions/34009653/convert-bytes-to-int
# https://stackoverflow.com/questions/2659312/how-do-i-convert-a-numpy-array-to-and-display-an-image
# https://www.geeksforgeeks.org/convert-a-numpy-array-to-an-image/
# https://www.geeksforgeeks.org/convert-python-nested-lists-to-multidimensional-numpy-arrays/
# https://stackoverflow.com/a/60352577
#
#########################