#!/usr/bin/env python3
#
# MUTATION CHAIN COMPUTATION TOOL
#
# Ever wondered what the complete history of your AFL crash file looks like?
# Now you can!
#
# This tool is developed to support file structures for parallel fuzzing runs using the
# naming of main/secondary as stated in the AFL docs (fuzzer01, fuzzer02 etc...)
# In case you want to use it for single instance runs just recreate the directory structure
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
        "--mode", 
        choices = ['single', 'all'], 
        help = 'compute chain for one file or all crash files in supplied directory. In single mode the -f argument is required', 
        required = True
    )

    parser.add_argument(
        "--dir",
        action = 'store',
        help = 'AFL output directory',
        required = True
    )

    parser.add_argument(
        "--instance",
        action = 'store',
        help = '[Only required in single mode] name of the fuzzer instance that contains the crash file supplied in the --file argument (e.g. \'fuzzer01\')',
        required = False
    )

    parser.add_argument(
        "--file",
        action = 'store',
        help = '[Only required in single mode] filename of specific crash file (e.g. \'id:000008,sig:06,src:000005,op:havoc,rep:8\')',
        required = False
    )

    args = parser.parse_args()

    if args.mode == "single":
        if args.file == None:
            parser.error("'--mode single' requires the '--file' argument.")
        elif args.instance == None:
            parser.error("'--mode single' requires the '--instance' argument.")


    afl_output_directory = args.dir

    # Create the interal representation of the various queues of parallel fuzzing instances
    for dir in os.listdir(afl_output_directory):
        if re.match("^fuzzer\\d+", dir):
            queues[dir] = fillDictWithFilenameKeys(afl_output_directory + '/' + dir + '/queue')

    if args.mode == "all":

        for dir in os.listdir(afl_output_directory):
            if re.match("^fuzzer\\d+", dir):
                for filename in os.listdir(afl_output_directory + '/' + dir + "/crashes"):
                    if re.match("^id:\\d+", filename):
                        print(filename)
                        crashes[filename] = compute_mutation_chain(filename, dir, 0)

    elif args.mode == "single":

        crashes[args.file] = compute_mutation_chain(args.file, args.instance, 0)

    print(json.dumps(crashes, sort_keys=True, indent=4))

if __name__ == '__main__':
    main()