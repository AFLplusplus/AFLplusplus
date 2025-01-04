#!/usr/bin/env python3
#
# MUTATION CHAIN COMPUTATION TOOL
#
# Ever wondered what the complete history of your AFL crash file looks like?
# Now you can!
#
# This tool is developed to support file structures for parallel fuzzing runs using the
# naming of main/secondary nodes as stated in the AFL docs (fuzzer01, fuzzer02 etc...)
# In case you want to use it for single node runs just recreate the directory structure
# which is used when parallel fuzzing is used (dump your results in a dir called fuzzer01).
#
# author: Maarten Dekker

# import required modules
import os, re, json
import argparse

crashes = {}
queues = {}

def fillDictWithFilenameKeys(dir):
    dict = {}
    for filename in os.listdir(dir):
        if re.match("^id:\\d+", filename):
            dict[filename] = None
    return dict

# recusively compute the chain of queue items that led to the AFL crash file
def compute_mutation_chain(filename, current_fuzzer, n):

    if re.match(".*src:(\\d+),", filename):

        source_id = re.match(".*src:(\\d+),", filename).group(1)
        file_we_look_for_rex = "^id:" + source_id + ","

        fuzzer_queue = None

        # determine if we need to look in the queue of another fuzzer instance
        if re.match(".*sync:(fuzzer\\d+),", filename):
            fuzzer_queue = re.match(".*sync:(fuzzer\\d+),", filename).group(1)
        else:
            fuzzer_queue = current_fuzzer

        for k,v in queues[fuzzer_queue].items():

            if re.match(file_we_look_for_rex, k):
               
                retval = {}
                retval[k] = compute_mutation_chain(k, fuzzer_queue, n+1)
                return retval

    # if the mutation result is a splice it thas 2 sources
    elif re.match(".*src:(\\d+)\\+(\\d+)", filename):

        sources = re.match(".*src:(\\d+)\\+(\\d+)", filename)

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
        return "seed"


def main():

    parser = argparse.ArgumentParser(
                    prog='mutation_chain.py',
                    description='Compute the mutation chain of AFL crash files to visulise the mutation history from seed files to crash' +
                    'This tool just dump json data to the CLI, it is advised to echo them into a file for further analysis (i.e. [command] >> your_file.json)',
                    epilog='Greetings from old zealand'
    )

    parser.add_argument(
        "-m", "--mode", 
        choices = ['single', 'all'], 
        help = 'compute chain for one file or all crash files in supplied directory. In single mode the -f argument is required', 
        required = True
    )

    parser.add_argument(
        "-i", "--input",
        action = 'store',
        help = 'Input directory for the mutation chain tool (the fuzzer\'s output directory)',
        required = True
    )

    parser.add_argument(
        "-n", "--node",
        action = 'store',
        help = '[Only used in single mode; optinal] name of the fuzzer node that contains the crash file supplied in the --file argument (e.g. \'fuzzer03\'). Defaults to \'fuzzer01\' if not supplied',
        required = False
    )

    parser.add_argument(
        "-f", "--file",
        action = 'store',
        help = '[Only used in single mode; required] filename of specific crash file (e.g. \'id:000008,sig:06,src:000005,op:havoc,rep:8\')',
        required = False
    )

    args = parser.parse_args()

    if args.mode == "single":

        if args.node == None:
            args.node = "fuzzer01"

        if args.file == None:
            parser.error("'--mode single' requires the '--file' argument.")

        crash_file_path = args.input + '/' + args.node + '/crashes/' + args.file
        if not os.path.isfile(crash_file_path):
            print("Error: \'" + crash_file_path + "\' does not exist.\nPlease verify whether the node and filename are correct.")
            return

    # Create the interal representation of the various queues of parallel fuzzing nodes
    for dir in os.listdir(args.input):
        if re.match("^fuzzer\\d+", dir):
            queues[dir] = fillDictWithFilenameKeys(args.input + '/' + dir + '/queue')

    if args.mode == "all":

        for dir in os.listdir(args.input):
            if re.match("^fuzzer\\d+", dir):
                for filename in os.listdir(args.input + '/' + dir + "/crashes"):
                    if re.match("^id:\\d+", filename):
                        print(filename)
                        crashes[filename] = compute_mutation_chain(filename, dir, 0)

    elif args.mode == "single":

        crashes[args.file] = compute_mutation_chain(args.file, args.node, 0)

    print(json.dumps(crashes, sort_keys=True, indent=4))

if __name__ == '__main__':
    main()