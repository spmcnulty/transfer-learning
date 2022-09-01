### angr-test.py
This is where the main control flow graph experiments are run, though the file has some extra code in it for learning angr the main bulk is creating CFG, vectorizing them with G2V, and then applying logistic regression to classify them between malware and benign. Since the difficulty of running this was troublesome I never created the means to add the file location from command line. The two important lines to change for running different experiments are Line [478](https://github.com/Dan-Laden/Binary-Classification-Graphs/blob/db07e141e0a86b97b5835403746ffa5c3189212f/angr-test.py#L478) and Line [490](https://github.com/Dan-Laden/Binary-Classification-Graphs/blob/db07e141e0a86b97b5835403746ffa5c3189212f/angr-test.py#L490). To run this file simply do 
```
python3 -O angr-test.py
```
