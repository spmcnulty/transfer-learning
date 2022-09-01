###########################
#
# author: Daniel Laden
# @ dthomasladen@gmail.com
#
###########################

import jsonlines #don't need the json library for this
import time
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import pandas as pd
import sklearn
import sklearn.model_selection as ms
import sklearn.naive_bayes as nb
from sklearn.model_selection import cross_validate
from sklearn.model_selection import cross_val_predict
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt

start_time = time.time()

########################### Functions

#
# Calculates the accuracy, recall, f1, and auc for the various methods note you can do a cross_validate like in this function but it's argue whether you can use that to caculate auc This should give an idea of S.D.
# but not an effective way to give an actually deviation of the data.
#
def analytics(model, X_test, y_test):
	y_pred = model.predict(X_test)
	#y_pred = cross_val_predict(model, X_test, y_test, cv=7)#not appropriate for evaluation methods

	#Prints all the relevant information we could ever ask for.
	print(model.score(X_test, y_test))
	print(confusion_matrix(y_test, y_pred))
	print(classification_report(y_test,y_pred))
	print(accuracy_score(y_test,y_pred))

	print("\t=\tCross-fold Validation\t=\n")

	cv = cross_validate(model, X_test, y_test, scoring=['accuracy','recall','f1','roc_auc'], cv=10)

	print("Mean\nAccuracy: %s\tRecall: %s\nF1: %s\tAUC: %s\n" % (round(cv['test_accuracy'].mean(), 3), round(cv['test_recall'].mean(), 3), round(cv['test_f1'].mean(), 3), round(cv['test_roc_auc'].mean(), 3)))
	print("Standard Deviation\nAccuracy: %s\tRecall: %s\nF1: %s\tAUC: %s" % (round(cv['test_accuracy'].std(), 3), round(cv['test_recall'].std(), 3), round(cv['test_f1'].std(), 3), round(cv['test_roc_auc'].std(), 3)))

###########################

small_test = []

#Train features

trained_func_tfidf = TfidfVectorizer() #list without dll included
trained_dll_tfidf = TfidfVectorizer() #List with dll included
counter = 0
with jsonlines.open('train_features_1.jsonl') as reader: #train_features_1 comes from the EMBER .jsonl dataset
	full_dll_list = [] #List with dll included
	full_func_list = [] #list without dll included

	code_list = []

	for obj in reader:
		counter += 1

		if counter == 50000:#5000 default
			break
		#print(obj)
		#print(obj.keys())
		#print(obj['label']) #0 benign, 1 malware, -1 unlabeled

		
		if obj['label'] == 1:
			#print("benign")
			#print("\n")
			#print(obj['byteentropy'])
			#print("\n")
			#print(obj['imports'])

			obj_imports = obj['imports']
			dll_list = ""
			function_list = ""
			for  dll in obj_imports:
				#print(dll)
				dll_list = dll_list + " " + dll
				for im in obj_imports[dll]:
					#print(im)
					function_list = function_list + " " + im

			#full_dll_list.append(dll_list + function_list)
			full_dll_list.append(dll_list)
			#full_func_list.append(function_list)

			code_list.append(obj['label'])

		elif obj['label'] == 0:
			#print("benign")
			#print("\n")
			#print(obj['byteentropy'])
			#print("\n")
			#print(obj['imports'])

			obj_imports = obj['imports']
			dll_list = ""
			function_list = ""
			for  dll in obj_imports:
				#print(dll)
				dll_list = dll_list + " " + dll
				for im in obj_imports[dll]:
					#print(im)
					function_list = function_list + " " + im

			#full_dll_list.append(dll_list + function_list)
			full_dll_list.append(dll_list)
			#full_func_list.append(function_list)

			code_list.append(obj['label'])

	#print(full_func_list)
	#X_func = trained_func_tfidf.fit_transform(full_func_list).toarray()
	X_dll = trained_dll_tfidf.fit_transform(full_dll_list).toarray()

	# print(X_func.shape)
	#print(X_dll.shape)

	(X_train, X_test, y_train, y_test) = ms.train_test_split(X_dll, code_list, test_size=.2)
	#(X_train, X_test, y_train, y_test) = ms.train_test_split(X_func, code_list, test_size=.2)

	#Naive Bayes classifier
	bnb = ms.GridSearchCV(nb.BernoulliNB(), param_grid={'alpha': np.logspace(-2., 2., 50)})
	bnb.fit(X_train, y_train)

	print("======Naive Bayes======\n")
	analytics(bnb, X_test, y_test)

	#Linear SVM Classifier
	classifier = SVC(kernel='linear')
	classifier.fit(X_train, y_train)

	print("\n\n======Linear SVM Classifier======\n")
	analytics(classifier, X_test, y_test)

	#rbf SVM Classifier
	classifier = SVC(kernel='rbf')
	classifier.fit(X_train, y_train)

	print("\n\n======RBF SVM Classifier======\n")
	analytics(classifier, X_test, y_test)

	#KNN classifier
	classifier = KNeighborsClassifier(n_neighbors=5)
	classifier.fit(X_train, y_train)

	print("\n\n======KNN Classifier n=5======\n")
	analytics(classifier, X_test, y_test)

	#KNN classifier
	classifier = KNeighborsClassifier(n_neighbors=7)
	classifier.fit(X_train, y_train)

	print("\n\n======KNN Classifier n=7======\n")
	analytics(classifier, X_test, y_test)

	#KNN classifier
	classifier = KNeighborsClassifier(n_neighbors=10)
	classifier.fit(X_train, y_train)

	print("\n\n======KNN Classifier n=10======\n")
	analytics(classifier, X_test, y_test)

	#Random Forest Classifier
	classifier = RandomForestClassifier(n_estimators=1500, random_state=0)
	classifier.fit(X_train, y_train)

	print("\n\n======Random Forest======\n")
	analytics(classifier, X_test, y_test)

	#Decision Tree Classifier
	classifier = DecisionTreeClassifier(max_leaf_nodes=3, random_state=0)
	classifier.fit(X_train, y_train)

	print("\n\n======Decision Tree======\n")
	analytics(classifier, X_test, y_test)

	# names = np.asarray(trained_dll_tfidf.get_feature_names())

	# print(",".join(names[np.argsort(bnb.best_estimator_.coef_[0, :])[::-1][:50]]))



print("--- Runtime of program is %s seconds ---" % (time.time() - start_time))

########################### References
#
# jsonlines.readthedocs.io/en/latest/
# https://stackabuse.com/k-nearest-neighbors-algorithm-in-python-and-scikit-learn/
# https://stackabuse.com/text-classification-with-python-and-scikit-learn/
# https://ipython-books.github.io/84-learning-from-text-naive-bayes-for-natural-language-processing/
# https://stackabuse.com/text-classification-with-python-and-scikit-learn/
#
# https://scikit-learn.org/stable/modules/model_evaluation.html#scoring-parameter
# https://scikit-learn.org/stable/modules/cross_validation.html
# https://www.dezyre.com/recipes/check-models-f1-score-using-cross-validation-in-python
# https://stackoverflow.com/questions/15286401/print-multiple-arguments-in-python
# https://gist.github.com/WittmannF/60680723ed8dd0cb993051a7448f7805
# https://scikit-learn.org/stable/modules/generated/sklearn.svm.SVC.html
#
###########################
