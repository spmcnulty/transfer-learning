import time
import os
import angr
import json
import multiprocessing

def binaryToCounts(filename):
    binary = angr.Project(filename, auto_load_libs=False)
    try:
        cfg = binary.analyses.CFGFast()
        cfg.normalize()
        total_binary_instr_counts = {}
        total_binary_vex_counts = {}
        functions_out_of_memory = []
        binary_breakdown = {}
        
        for func_node in cfg.functions.values():
            function_counts = {}
            function_name = func_node.name
            counts_per_instr_block = {}
            counts_per_vex_block = {}
            addr = func_node.addr
            
            if func_node.name.startswith("__"):
                functions_out_of_memory.append(function_name)
                continue
            else:
                for block in func_node.blocks:
                    for instr in block.capstone.insns:
                        if instr.mnemonic in counts_per_instr_block.keys():
                            counts_per_instr_block[instr.mnemonic] += 1
                        else:
                            counts_per_instr_block[instr.mnemonic] = 1
                        if instr.mnemonic in total_binary_instr_counts.keys():
                            total_binary_instr_counts[instr.mnemonic] += 1
                        else:
                            total_binary_instr_counts[instr.mnemonic] = 1
                    try:
                        vex_block = block.vex
                        if stmt.tag in counts_per_vex_block.keys():
                            counts_per_vex_block[stmt.tag] += 1
                        else:
                            counts_per_vex_block[stmt.tag] = 1
                        if stmt.tag in total_binary_vex_counts.keys():
                            total_binary_vex_counts[stmt.tag] += 1
                        else:
                            total_binary_vex_counts[stmt.tag] = 1
                    except Exception as e:
                        functions_out_of_memory.append(function_name)

                if counts_per_instr_block and counts_per_vex_block:
                    function_counts[addr] = {"Instruction Counts" : counts_per_instr_block, "Vex Counts" : counts_per_vex_block}
            binary_breakdown[function_name] = function_counts
        return ({"Total Counts" : {"Instruction Counts" : total_binary_instr_counts,"Vex Counts" : total_binary_vex_counts}, "Function Counts" : binary_breakdown, "OoM Functions" : functions_out_of_memory})
    except Exception as e:
        print("\033[91m\n\n\nError: %s" % (e))
        print("File %s failed to run skipping this file\n\n\n\033[0m" % (filename))

#subfunction for multiprocessing
def store_funct(filepath,df):
    temp_var = binaryToCounts(filepath)
    instr_count = temp_var['Total Counts']['Instruction Counts']
    output_name = output_path+'instruction_counts_'+df+'.json'
    with open(output_name,'w') as outfile:
    	json.dump(instr_count,outfile,indent='  ')

data_path = "../Data/pe-machine-learning-dataset/samples/"
output_path = "./Data/test/"
sec_to_wait = 300

import logging
loggers = [logging.getLogger()]  # get the root logger
loggers = loggers + [logging.getLogger(name) for name in logging.root.manager.loggerDict]
for logger in loggers:
    logger.setLevel(100)

if not os.path.exists(output_path): os.makedirs(output_path)

filenames = os.listdir(data_path)
filenames = filenames[:5]
start_time = time.time()

for df in filenames:
    filepath = data_path+df
    try:
        file = open(filepath, "rb")
    except:
        continue
        
    #multiprocessing in order to quit function after a certain amount of time
    #The name variable is necessary, but the value is unimportant
    p = multiprocessing.Process(target=store_funct, name='Foo', args=(filepath,df))
    p.start()
    count = 0
    while count <= sec_to_wait and p.is_alive():
        count += 1
        time.sleep(1)
    p.terminate()
		
print("--- Runtime of program is %s seconds ---" % (time.time() - start_time))
