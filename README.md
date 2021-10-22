# transfer-learning
A collection of data, code, experiments, results, and writeups for Transfer Learning

### angr-test.py
This is where the main control flow graph experiments are run, though the file has some extra code in it for learning angr the main bulk is creating CFG, vectorizing them with G2V, and then applying logistic regression to classify them between malware and benign. Since the difficulty of running this was troublesome I never created the means to add the file location from command line. The two important lines to change for running different experiments are Line [478](https://github.com/Dan-Laden/Binary-Classification-Graphs/blob/db07e141e0a86b97b5835403746ffa5c3189212f/angr-test.py#L478) and Line [490](https://github.com/Dan-Laden/Binary-Classification-Graphs/blob/db07e141e0a86b97b5835403746ffa5c3189212f/angr-test.py#L490). To run this file simply do 
```
python3 -O angr-test.py
```

### ember-data-test.py
NLP style experiments on the ember dataset, since the dataset is stripped binaries they're not exactly what we have as data on Redshift, however we can get similar things out of binaries using angr. The main objective here was to somewhat recreate the @Disco paper. Conclusion: It would be better to have @Disco to ensure correctness as the output
seems quite different.
```
python3 ember-data-test.py
```

### binary-to-image-test.py
Using [this](https://dl.acm.org/doi/pdf/10.1145/2016904.2016908) paper this method is recreated to turn binaries into a black and white picture representation. mal-net goes a step furthur and splits the header, sectional, and main parts of a binary into different colors r,b,g for each different part.
```
python3 binary-to-image-test.py
```

### Image-TL-experiment.py
We tested many different ML and Deep Learning packages. We were looking for one that could take previous models and have specifications on how to retrain - specifically, freezing certain weights and layers and allowing fine-tuning on other layers. This file presents the standard file we will use for running our Image representations. We can transfer from Image databases and we can transfer from Malware detection to vulnerability code.
'''
python3 Image-TL-experiment.py
'''
