###########################
#
# author: Daniel Laden
# @ dthomasladen@gmail.com
#
###########################
# This creates a deep autoencoder

import keras
from keras.layers import Input, Dense
from keras.models import Model
from keras.datasets import mnist

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time

start_time = time.time()

########################### Data setup

(X_train, _), (X_test, _) = mnist.load_data()

X_train = X_train.astype('float32')/255
X_test = X_test.astype('float32')/255

X_train = X_train.reshape(len(X_train), np.prod(X_train.shape[1:]))
X_test = X_test.reshape(len(X_test), np.prod(X_test.shape[1:]))

# print(X_train.shape)
# print(X_test.shape)

########################## Deep Encoder Setup

input_img= Input(shape=(784,))


encoded = Dense(units=128, activation='relu')(input_img)
encoded = Dense(units=64, activation='relu')(encoded)
encoded = Dense(units=32, activation='relu')(encoded)

decoded = Dense(units=64, activation='relu')(encoded)
decoded = Dense(units=128, activation='relu')(decoded)
decoded = Dense(units=784, activation='sigmoid')(decoded)

autoencoder = Model(input_img, decoded)

encoder = Model(input_img, encoded)

autoencoder.summary()

autoencoder.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

########################### Autoencoder training

autoencoder.fit(X_train, X_train,
	epochs=50,
	batch_size=256,
	shuffle=True,
	validation_data=(X_test, X_test))

encoded_imgs = encoder.predict(X_test)
predicted = autoencoder.predict(X_test)


########################### Visualization

n = 20 #how many digits to display
plt.figure(figsize=(40,4))
for i in range(10):
	#Display original
	ax = plt.subplot(3, n, i+1)
	plt.imshow(X_test[i].reshape(28,28))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)

	#Display encoded images
	ax = plt.subplot(3, n, i+1+n)
	plt.imshow(encoded_imgs[i].reshape(8,4))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)


	#Display reconstruaction
	ax = plt.subplot(3, n, 2*n +i+1)
	plt.imshow(predicted[i].reshape(28,28))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)


plt.show()


########################## Denoising Encoder START

########################## Data set up

(X_train, _), (X_test, _) = mnist.load_data()

X_train = X_train.astype('float32')/255
X_test = X_test.astype('float32')/255

X_train = X_train.reshape(len(X_train), np.prod(X_train.shape[1:]))
X_test = X_test.reshape(len(X_test), np.prod(X_test.shape[1:]))

X_train_noisy = X_train + np.random.normal(loc=0.0, scale=0.5, size=X_train.shape)
X_train_noisy = np.clip(X_train_noisy, 0.,1.)

X_test_noisy = X_test + np.random.normal(loc=0.0, scale=0.5, size=X_test.shape)
X_test_noisy = np.clip(X_test_noisy, 0.,1.)

# print(X_train.shape)
# print(X_test.shape)

########################## Denoisy Encoder Setup

input_img= Input(shape=(784,))


encoded = Dense(units=128, activation='relu')(input_img)
encoded = Dense(units=64, activation='relu')(encoded)
encoded = Dense(units=32, activation='relu')(encoded)

decoded = Dense(units=64, activation='relu')(encoded)
decoded = Dense(units=128, activation='relu')(decoded)
decoded = Dense(units=784, activation='sigmoid')(decoded)

autoencoder = Model(input_img, decoded)

encoder = Model(input_img, encoded)

autoencoder.summary()

autoencoder.compile(optimizer='adadelta', loss='binary_crossentropy', metrics=['accuracy'])

########################### Autoencoder training

autoencoder.fit(X_train_noisy, X_train_noisy,
	epochs=100,
	batch_size=256,
	shuffle=True,
	validation_data=(X_test_noisy, X_test_noisy))

encoded_imgs = encoder.predict(X_test_noisy)
predicted = autoencoder.predict(X_test_noisy)


########################### Visualization

n = 20 #how many digits to display
plt.figure(figsize=(40,4))
for i in range(10):
	#Display original
	ax = plt.subplot(4, n, i+1)
	plt.imshow(X_test[i].reshape(28,28))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)



	#Display noisy images
	ax = plt.subplot(4, n, i+1+n)
	plt.imshow(X_test_noisy[i].reshape(28,28))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)


	#Display encoded images
	ax = plt.subplot(4, n, 2*n +i+1)
	plt.imshow(encoded_imgs[i].reshape(8,4))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)

	#Display reconstruction
	ax = plt.subplot(4, n, 3*n +i+1)
	plt.imshow(predicted[i].reshape(28,28))
	plt.gray()
	ax.get_xaxis().set_visible(False)
	ax.get_yaxis().set_visible(False)


plt.show()

print("--- Runtime of program is %s seconds ---" % (time.time() - start_time))

########################### References
#
# medium.datadriveninvestor.com/deep-autoencoder-using-keras-b77cd3e8be95
#
###########################