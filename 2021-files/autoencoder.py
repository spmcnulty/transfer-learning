###########################
#
# author: Daniel Laden
# @ dthomasladen@gmail.com
#
###########################
# This creates autoencoders for a normal and sparse encoder.

import keras
from keras import layers
from keras import regularizers
from keras.datasets import mnist

import numpy as np
import matplotlib.pyplot as plt
import time

start_time = time.time()

########################### Data setup

(x_train, _), (x_test, _) =mnist.load_data()

#Data normalization between 0 and 1. Flatten 28x28 images to vectors of sie 784
x_train = x_train.astype('float32') / 255.
x_test = x_test.astype('float32') / 255.
x_train = x_train.reshape((len(x_train), np.prod(x_train.shape[1:])))
x_test = x_test.reshape((len(x_test), np.prod(x_test.shape[1:])))
print(x_train.shape)
print(x_test.shape)

########################### Normal encoder

# #This is the size of our encoded representations
encoding_dim = 32 #32 floats -> compression of factor 24.5, assuming the input is 784 floats

#This is our input image
input_img = keras.Input(shape=(784,))

encoded = layers.Dense(encoding_dim, activation='relu')(input_img)
decoded = layers.Dense(784, activation='sigmoid')(encoded)

autoencoder = keras.Model(input_img, decoded)

########################### Sparse Encoder

encoding_dim = 32

input_img = keras.Input(shape=(784,))

encoded = layers.Dense(encoding_dim, activation='relu',
	activity_regularizer=regularizers.l1(10e-5))(input_img)
decoded = layers.Dense(784, activation='sigmoid')(encoded)

autoencoder = keras.Model(input_img, decoded)

########################### Model creation

encoder = keras.Model(input_img, encoded)


#Create the decoder model
encoded_input = keras.Input(shape=(encoding_dim,))

decoder_layer = autoencoder.layers[-1]

decoder = keras.Model(encoded_input, decoder_layer(encoded_input))


#configuring the autoencoder to use per-pixel binary crossentropy loss, and Adam optimizer
autoencoder.compile(optimizer='adam', loss='binary_crossentropy')


########################### Autoencoder training

autoencoder.fit(x_train, x_train,
	epochs=250,
	batch_size=256,
	shuffle=True,
	validation_data=(x_test, x_test))

encoded_imgs = encoder.predict(x_test)
decoded_imgs = decoder.predict(encoded_imgs)


########################### Visualization

n = 10 #how many digits to display
plt.figure(figsize=(20,4))
for i in range(n):
	#Display original
	ax = plt.subplot(2, n, i+1)
	plt.imshow(x_test[i].reshape(28,28))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)

	#Display reconstruaction
	ax = plt.subplot(2, n, i+1+n)
	plt.imshow(decoded_imgs[i].reshape(28,28))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)
plt.show()

print("--- Runtime of program is %s seconds ---" % (time.time() - start_time))
