#
# MUTATION CHAIN COMPUTATION TOOL
#
# Ever wondered what the complete history of your AFL crash file looks like?
# Now you can!
#
# This tool is developed to support file structures for parralel fuzzing runs using the
# naming of master/slaves as stated in the AFL docs (fuzzer01, fuzzer02 etc...)
# In case you want to use it for single instance runs slight modifications are required
# 
# Best to echo the output of this tool into a json file for further analysis.
#
# author: Maarten Dekker

# import required module
import os, re, json

# user config section
afl_output_directory = "INSERT_YOUR_AFL_OUTPUT_DIRECTORY"

crashes = {}
queues = {}

# Create the interal representation of the various queues of parrallel fuzzing instances
def fillDictWithFilenameKeys(dir):
    dict = {}
    for filename in os.listdir(dir):
        if re.match("^id:\d+", filename):
            dict[filename] = None
    return dict

for dir in os.listdir(afl_output_directory):
    if re.match("^fuzzer\d+", dir):
        queues[dir] = fillDictWithFilenameKeys(afl_output_directory + '/' + dir + '/queue')

# recusively compute the chain of queue items that led to the AFL crash file
def compute_mutation_chain(filename, current_fuzzer, n):

    if re.match(".*src:(\d+),", filename):

        source_id = re.match(".*src:(\d+),", filename).group(1)
        file_we_look_for_rex = "^id:" + source_id + ","

        fuzzer_queue = None

        # determine if we need to look in the queue of another fuzzer instance
        if re.match(".*sync:(fuzzer\d+),", filename):
            fuzzer_queue = re.match(".*sync:(fuzzer\d+),", filename).group(1)
        else:
            fuzzer_queue = current_fuzzer

        for k,v in queues[fuzzer_queue].items():

            if re.match(file_we_look_for_rex, k):
               
                retval = {}
                retval[k] = compute_mutation_chain(k, fuzzer_queue, n+1)
                return retval

    # if the mutation result is a splice it thas 2 sources
    elif re.match(".*src:(\d+)\+(\d+)", filename):

        sources = re.match(".*src:(\d+)\+(\d+)", filename)

        source_id_1 = sources.group(1)
        source_id_2 = sources.group(2)

        file_we_look_for_1_rex = "^id:" + source_id_1 + ","
        file_we_look_for_2_rex = "^id:" + source_id_2 + ","

        # for mutation with two sources, the sources are never synced form other queues
        retval = {}

        for k,v in queues[current_fuzzer].items():

            if re.match(file_we_look_for_1_rex, k):
                retval[k] = compute_mutation_chain(k, current_fuzzer, n+1)

            elif re.match(file_we_look_for_2_rex, k):
                retval[k] = compute_mutation_chain(k, current_fuzzer, n+1)

        return retval

    else:
        return "Reached original"

for dir in os.listdir(afl_output_directory):
    if re.match("^fuzzer\d+", dir):
        for filename in os.listdir(afl_output_directory + '/' + dir + "/crashes"):
            if re.match("^id:\d+", filename):
                crashes[filename] = compute_mutation_chain(filename, dir, 0)

print(json.dumps(crashes, sort_keys=True, indent=4))