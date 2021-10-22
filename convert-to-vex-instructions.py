###########################
#
# author: Daniel Laden
# @ dthomasladen@gmail.com
#
###########################
#angr test file

import angr
#from angrutils import * #Has errors trying to load this on Redshift? But doesn't seem necessary
import monkeyhex
import networkx as nx
from node2vec import Node2Vec
import json
import time
import numpy as np
import pyvis

from karateclub.graph_embedding import Graph2Vec
from karateclub.graph_embedding import GL2Vec
from karateclub.graph_embedding import IGE
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import LogisticRegression

from pyvis.network import Network
import os
from os import walk

start_time = time.time()

#test data not for experiments
#binary = angr.Project("wsmprovhost.exe")
#binary = angr.Project("SlackSetup.exe")

###########################
#functions

#
# Takes a file and returns a count of all instructions and vex instructions using angr
#
def binaryToCounts(filename):
    binary = angr.Project(filename, auto_load_libs=False)
    try:
        cfg = binary.analyses.CFGFast()
		#Prints all the functions in the binary as well as the address of the function in the binary
        #print(binary.kb.functions.items())
#        print("Instructions:")
#        for func in binary.kb.functions.values():
#            print("[+] Function {}, found at {}".format(func.name, hex(func.addr)))
#        print("end instructions")
        cfg.normalize()
        total_binary_instr_counts = {}
        total_binary_vex_counts = {}
        functions_out_of_memory = []
        binary_breakdown = {}
        
        for func_node in cfg.functions.values():
            function_counts = {}
            function_name = func_node.name

			#print(function_name)
            counts_per_instr_block = {}
            counts_per_vex_block = {}
            addr = func_node.addr
            
            if func_node.name.startswith("__"): #outside function we don't need to pull the code from these
                print("\033[93m\nOutside function %s detected skipping over this function.\n\033[0m" % (function_name))
                functions_out_of_memory.append(function_name)
                continue
            else:
                for block in func_node.blocks:

					#Get the instruction counts for a binary
#                    block.pp() # pretty print to see what a block looks like
                    for instr in block.capstone.insns:
#                        print(instr.mnemonic)
                        if instr.mnemonic in counts_per_instr_block.keys():
                            counts_per_instr_block[instr.mnemonic] += 1
                        else:
                            counts_per_instr_block[instr.mnemonic] = 1

						#Add to the total counts for the binary
                        if instr.mnemonic in total_binary_instr_counts.keys():
                            total_binary_instr_counts[instr.mnemonic] += 1
                        else:
                            total_binary_instr_counts[instr.mnemonic] = 1
                        #print(counts_per_instr_block) # Print to check proper counts

					#Get the vex instruction count as well
                    try:
                        vex_block = block.vex
						#vex_block.pp()
                        for stmt in vex_block.statements:
                            print(stmt.tag)
                        if stmt.tag in counts_per_vex_block.keys():
                            counts_per_vex_block[stmt.tag] += 1
                        else:
                            counts_per_vex_block[stmt.tag] = 1

						#Add to the total counts for the binary
                        if stmt.tag in total_binary_vex_counts.keys():
                            total_binary_vex_counts[stmt.tag] += 1
                        else:
                            total_binary_vex_counts[stmt.tag] = 1
					#print(counts_per_block) # Print to check proper counts
                    except Exception as e:
                        print("\033[91m\nError: %s" % (e))
                        print("Function %s failed to run vex skipping this function\n\033[0m" % (function_name))
                        functions_out_of_memory.append(function_name)

                if counts_per_instr_block and counts_per_vex_block:
                    function_counts[addr] = {"Instruction Counts" : counts_per_instr_block, "Vex Counts" : counts_per_vex_block}
                    print(function_counts)
                else:
                    continue

			# A test print to make sure it's getting instruction counts
			# if function_counts and switcher:
			# 	print(function_counts)
			# else:
			# 	pass
            binary_breakdown[function_name] = function_counts

		#print(binary_breakdown)
        return ({"Total Counts" : {"Instruction Counts" : total_binary_instr_counts,"Vex Counts" : total_binary_vex_counts}, "Function Counts" : binary_breakdown, "OoM Functions" : functions_out_of_memory})
    except Exception as e:
        print("\033[91m\n\n\nError: %s" % (e))
        print("File %s failed to run skipping this file\n\n\n\033[0m" % (filename))
#        time.sleep(5)


#
# Takes a list of filenames(could be changed to directory later) and creates a JSON representation of the data.
#
def filesToJSON(filename_list):
	data = {}
	for filename in filename_list:
		counts = binaryToCounts(filename)

		data[filename] = counts

	with open('Binary-file-counts.json', 'w') as outfile:
		json.dump(data, outfile, indent=2)


#
# Runs the test for a given graph embedding model for Logistic Regression(a basic method)
#
def modelTest(model, graphs, y):
	model.fit(graphs)

	X = model.get_embedding()

	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

	#Uses logistric regression to fit the data and make classification decisions
	downstream_model = LogisticRegression(random_state=0, max_iter=20000).fit(X_train, y_train)
	y_hat = downstream_model.predict_proba(X_test)[:, 1]
	auc = roc_auc_score(y_test, y_hat)
	print('AUC: {:.4f}'.format(auc))


#
# Given a set of binary files this will output a list of cfgs for those binaries
#
def buildCFGGraphs(files, y):
	graphs = []
	index = 0
	for fe in files:
		try:
			binary = angr.Project(fe, auto_load_libs=False)
			cfg = binary.analyses.CFGFast()
			cfg = cfg.graph
			cfg = cfg.to_undirected()
			graphs.append(cfg)
			index+=1

		# This exception shows so the file that errors out and has some time for a user to see the popup before continuing
		# Change this if you wanna collect what gets removed from the dataset or etc
		except Exception as e:
			print("\033[91m\n\n\nError: %s" % (e))
			print("File %s failed to run skipping this file\n\n\n\033[0m" % (fe))
			del y[index]
			time.sleep(30)
		

	return graphs, y


#
# Given a set of binary files this will output a list of ddgs for those binaries
#
def buildDDGGraphs(files):
	graphs = []
	for file in files:
		binary = angr.Project(file, auto_load_libs=False)
		cfg = binary.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=2)

		#Generate the control dependence graph
		print("\n\n\nCDG being built...\n\n\n")
		time.sleep(10)
		cdg = binary.analyses.CDG(cfg)

		#Build the data dependence graph. Might take time
		print("\n\n\nDDG being built...\n\n\n")
		time.sleep(10)
		ddg = binary.analyses.DDG(cfg)

		graphs.append(ddg)

		#
		# This block bellow is testing code to see what data types exist within the ddg object.
		#
		#['data_graph', 'data_sub_graph', 'dbg_repr', 'errors', 'find_consumers', 'find_definitions', 
		#'find_killers', 'find_sources', 'function_dependency_graph', 'get_predecessors', 'graph', 'kb', 
		#'log', 'named_errors', 'pp', 'project', 'simple_view', 'simplified_data_graph', 'view'
		#print(dir(ddg))
		# print("\n\n\n")
		# print(type(ddg.data_graph))
		# print("\n\n\n")
		# print(type(ddg.data_sub_graph))
		# print("\n\n\n")
		# print(type(ddg.graph))
		# print("\n\n\n")
		# print(dir(ddg.view))
		# print("\n\n\n")
		# print(dir(ddg.kb))
		# print("\n\n\n")
		#print(ddg.pp()) #prints out the list of pointers for data 
		# for node in ddg.graph.nodes():
		# 	print(dir(node))
		# 	print(type(node))
		# 	# print(node.context)
		# 	# print(node.info)
		# 	break

	return graphs


#
# We need the largest connected component because Graph2Vec doesn't work with disconnected graphs(?)
# This function will cycle through and find the graph with the most edges within it.
#
def findMostConnectedGraph(graphs, files):
	#switcher = True
	max_graphs = []
	for graph, file in zip(graphs, files):
		most_connected = 0
		most_connected_graph = None
		components = [graph.subgraph(c).copy() for c in nx.connected_components(graph)]
		for idx, g in enumerate(components,start=1):
			if len(g.edges()) > most_connected:
				#print("Old value: %d\tNew value: %d" % (most_connected, len(g.edges())))
				most_connected = len(g.edges())
				most_connected_graph = g
				#time.sleep(0.5)
			#Test components
			# print("Components %d: Nodes: %s Edges %s" % (idx, str(g.nodes()), str(g.edges())))
			# print(len(g.edges()))
			# if not switcher:
			# 	break
			# else:
			# 	print(g.edges())
		# switcher = False
		if most_connected_graph:
			max_graphs.append(most_connected_graph)
			print(len(most_connected_graph.edges()))
		else: #Raise an error for that file
			print("File %s failed to run quiting program\n\n\n\033[0m" % (file))
			quit()
	return max_graphs


#
# Change the node mappings due to CFGNode comparison errors switches them to the function name
#
def swapNodeMapping(graphs):
	new_graphs = []
	for graph in graphs:
		G = nx.Graph()
		nodes = []
		edges = []
		for node in graph.nodes():
			if node.name:
				nodes.append(node.name) #using the function's address for the remapping use node.addr
			else:
				nodes.append(str(node.addr))
		for edge in graph.edges():
			if edge[0].name and edge[1].name: # might cause errors with resolving things to .addr when it doesn't need

				e = (edge[0].name, edge[1].name)
				edges.append(e)
			elif edge[0].name:
				e = (edge[0].name, edge[1].addr)
			elif edge[1].name:
				e = (edge[0].addr, edge[1].name)
			else:
				e = (str(edge[0].addr), str(edge[1].addr))
				edges.append(e)
			
		G.add_nodes_from(nodes)
		G.add_edges_from(edges)
		new_graphs.append(G)

	return new_graphs


#
# Creates html visualizations for all given graphs
#
def createDDGVisualization(graphs, files):
	for file, ddg in zip(files, graphs):
		ddg_graph = fixDDGNodes(ddg.graph)

		net = Network(notebook=True)
		net.from_nx(ddg_graph)
		filename = file + "-ddg.html"
		net.show(filename)


#
# gets around the annoying code object so we can do visualization
#
def fixDDGNodes(ddg):
	G = nx.Graph()
	nodes = []
	edges = []
	for node in ddg.nodes():
		if not node.block_addr: #ignore nonetype returned addresses OoM addresses?
			continue
		nodes.append(node.block_addr)
	for edge in ddg.edges():
		e = (edge[0].block_addr, edge[1].block_addr)
		if e[1] == e[0]: #skip self representation
			continue
		elif not e[1] or not e[0]: #ignore nonetype returned addresses OoM addresses?
			continue
		edges.append(e)

	# print(nodes)
	# print(edges)
	G.add_nodes_from(nodes)
	G.add_edges_from(edges)
	return G


#
# gets around the annoying code object so we can do visualization
#
def fixVSANodes(ddg):
	G = nx.Graph()
	nodes = []
	edges = []
	for node in ddg.nodes():
		#print(dir(node))
		if not node.addr: #ignore nonetype returned addresses OoM addresses?
			continue
		nodes.append(node.addr)
	for edge in ddg.edges():
		e = (edge[0].addr, edge[1].addr)
		if e[1] == e[0]: #skip self representation
			continue
		elif not e[1] or not e[0]: #ignore nonetype returned addresses OoM addresses?
			continue
		edges.append(e)

	# print(nodes)
	# print(edges)
	G.add_nodes_from(nodes)
	G.add_edges_from(edges)
	return G


######################
# Code for learning the functions of Angr

#
# Basic properties
#

#print(binary.arch) DWO


#
# The loader
#
#print("\n==========#print("\n===================Loaded Objects===================\n")

#print(binary.loader.shared_objects) #will vary per object

#print("Program has an executable stack? %s\n" % (binary.loader.main_object.execstack))



#
# Deeper loader information
#

#All loaded in elf objects
#ll_elf = binary.loader.all_elf_objects 

#All external objects that help with unresolved imports
#external = binary.loader.extern_object

#Object used to provide addresses for emulated syscalls
#kernel = binary.loader.kernel_object



#
# Object Metadata
#
#main_binary = binary.loader.main_object
#print("\n===================Included Sections===================\n")
#for obj in main_binary.sections:
#	print(obj)
#print("\n===================Included Sections===================\n")

#dot_text = main_binary.find_segment_containing(main_binary.entry)

#print(dir(dot_text))



#
# Basic Block extraction
#

#block = binary.factory.block(main_binary.entry)
#print(block)

#print("Program has %d instructions\n" % (int(block.instructions)))

#Prints the disassembly instructions
#print(block.pp())

#
# Additional block representations
#

# capstone_block = block.capstone
# #print(capstone_block)

# pyvex_block = block.vex
# #print(pyvex_block)

#
# Binary Counts
#
counts = binaryToCounts("wsmprovhost.exe")

# #
# # Export JSON file
# #
#files = ["test-binary.o", "bluetoothd", "SlackSetup.exe", "crtfastmath.o", "libssl3.so", "NetworkManager", "dumpexfat", "openvpn"]
# files = ["test-binary.o", "dumpexfat", "openvpn", "bowling-score.o", "pokemon-effectiveness.o", "bluetoothd", "NetworkManager", "sm_text.o", "SlackSetup.exe"]
# malware_files = ["8a0ce112e22f2e497f35379ada2be8626e424c2849aec0162f82aff9baa83c99", "8a0ce216b4ee1eb9bff7a251ec9a9e25eb6a83a0a6f92ca2ad768b27e71f6db8", "8a0cebd00be58d9f72905bf6fd574f00350e5ef2b98d6c197be72d6989b4b675", "8a0cf9b4a94786ea14f8cc57bcec2dc0a8a9dcf14669fa9810fcc3b5705af786", "8a0ceff6ba0a120697057f2640141f19dbb92e6f1b9012463e1e7b34a97149b8"]
# malware2 = ["8a0d0a8cb965af7a49fc3283b12b67010f423584a164998e07d0b28297185945", "8a0d8bbaf5680162c1f452d0f0badf88b9c2b0f5a663c25e7e0eb71c23b5a6a1", "8a0d36cbaf28790439e05a19c24dc2f4fd02e3f820ea8650075f6d0f77045ce8"]
# malware_files = malware_files + malware2

# End of code for angr learning
############################################

############################################
# Start of running experiments code


# Benign data
mypath = "..\\Data\\binaries\\"
f_benign = []
y_benign = []
#print("Benign mypath is")
#print(mypath)
for (dirpath, dirnames, filenames) in walk(mypath):
#	print(dirpath)
	for f in filenames:
		file_b = dirpath + f
		f_benign.append(file_b)
		y_benign.append(0)
	break

# Malware Data
mypath = "..\\Data\\binaries\\"
f_malware = []
y_malware = []
#print("malware path")
for (dirpath, dirnames, filenames) in walk(mypath):
#	print(dirpath)
	for f in filenames:
		file_m = dirpath + f
		f_malware.append(file_m)
		y_malware.append(1)
	break

#print(f_malware[:10])
#print(f_benign[:10])


files = f_benign + f_malware
y = y_benign + y_malware

#print(y[:10])
#print(y[-10:])

# for malware in malware_files:
# 	malware = directory + malware
# 	files.append(malware)
# #files = ["test-binary.o", "bowling-score.o", "pokemon-effectiveness.o", "sm_text.o"]
# y = [0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1]
# filesToJSON(files)


#
# Graph Analysis
#
#graphs = buildCFGGraphs(files, y)
#y = graphs[1]
#graphs = graphs[0]
#opt_graphs = findMostConnectedGraph(graphs, files)
#remapped_graphs = swapNodeMapping(opt_graphs)


# # print(max_graphs[0].edges())
#model = Graph2Vec()
#model.fit(remapped_graphs)
#X = model.get_embedding()
#print(X)


#Tests three different g2v like models
#model = Graph2Vec()
#model2 = GL2Vec()
#model3 = IGE()
#modelTest(model,remapped_graphs,y)
#modelTest(model2,remapped_graphs,y)
#modelTest(model3,remapped_graphs,y)
#print("\n\n\n")
#print(len(y))
#time.sleep(30)


# Code for the DDG that didn't work in the long run
# graphs = buildDDGGraphs(files)
# 
# createDDGVisualization(graphs, files)


#
# VSA work; VSA didn't work in the long run
#
# binary = angr.Project("dumpexfat", use_sim_procedures=True, auto_load_libs=False)
# cfg = binary.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=4)
# 
# 
# #Build the Value set analysis. Might take time
# print("\n\n\nVSA being built...\n\n\n")
# time.sleep(5)
# vfg = binary.analyses.VFG(cfg, function_start=binary.entry, context_sensitivity_level=1, interfunction_level=3, max_iterations=80)
# 
# #
# #'abort', 'copy', 'errors', 'final_states', 'function_final_states', 'function_initial_states', 
# #'get_any_node', 'graph', 'has_job', 'irsb_from_node', 'jobs', 'kb', 'log', 'named_errors', 'project', 'should_abort'
# print(dir(vfg))
# print(vfg)
# 
# vfg_graph = fixVSANodes(vfg.graph)
# 
# net = Network(notebook=True)
# net.from_nx(vfg_graph)
# filename = "dumpexfat" + "-vfg.html"
# net.show(filename)



print("--- Runtime of program is %s seconds ---" % (time.time() - start_time))


#
# Angr visualization with .CFGEmulated not working?
#
# binary = angr.Project("putty.exe", auto_load_libs=False)
# # main_binary = binary.loader.main_object
# # main = binary.loader.main_object.get_symbol(main_binary.entry)
# # print(main)
# # start_state = binary.factory.blank_state(addr=main.rebased_addr)
# cfg = binary.analyses.CFGEmulated(fail_fast=True)
# plot_cfg(cfg, "putty.exe_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)

#########################
#
# https://docs.angr.io/core-concepts/toplevel
# https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/
# https://stackoverflow.com/a/2259250
# https://reverseengineering.stackexchange.com/a/24666
# http://angr.io/api-doc/angr.html#angr.analyses.disassembly.Disassembly
# https://stackoverflow.com/questions/40243753/exception-dot-not-found-in-path-in-python-on-mac
#
# https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/analyzing-functions
# https://docs.angr.io/advanced-topics/ir
#
# https://github.com/eliorc/node2vec/issues/5
# https://karateclub.readthedocs.io/en/latest/notes/introduction.html
#
# https://stackoverflow.com/questions/6886493/get-all-object-attributes-in-python
# https://stackabuse.com/reading-and-writing-json-to-a-file-in-python
# https://www.delftstack.com/howto/python/python-print-colored-text/
#
# https://networkx.org/documentation/stable/reference/classes/generated/networkx.DiGraph.to_undirected.html
# https://stackoverflow.com/questions/48820586/removing-isolated-vertices-in-networkx
# https://networkx.org/documentation/stable/reference/generated/networkx.relabel.relabel_nodes.html
# https://stackoverflow.com/questions/21739569/finding-separate-graphs-within-a-graph-object-in-networkx
#