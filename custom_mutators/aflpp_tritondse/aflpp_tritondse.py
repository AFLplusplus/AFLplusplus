import sys
import os
import logging
import hashlib

from tritondse import Config
from tritondse import CoverageStrategy
from tritondse import ProcessState
from tritondse import Program
from tritondse import CleLoader
from tritondse import Seed
from tritondse import SeedFormat
from tritondse import SymbolicExecutor
from tritondse import SymbolicExplorator


#logging.basicConfig(level=logging.INFO)

is_debug = False
out_path = ""
input_file = None
prog = None
config = None
dse = None
cycle = 0
count = 0
hashes = set()

def pre_exec_hook(se: SymbolicExecutor, state: ProcessState):
    #logging.info(f"[PRE-EXEC] Processing seed: {se.seed.hash}, \
    #                ({repr(se.seed.content)})")
    global count
    global hashes
    print('DEBUG - prehook')
    if se.seed.hash not in hashes:
        hashes.add(se.seed.hash)
        filename = out_path + "/id:" + f"{count:06}" + "," + se.seed.hash
        if not os.path.exists(filename):
            if is_debug:
                print('Creating queue input ' + filename)
            with open(filename, 'wb') as file:
                file.write(se.seed.content)
                count += 1
    else:
        print('has hash: ' + se.seed.hash)
    if input_file:
        if is_debug:
            print('Writing to ' + input_file + ' the content: ' + str(se.seed.content))
        with open(input_file, 'wb') as file:
            file.write(se.seed.content)
    else:
        print('no input!')


def init(seed):
    global prog
    global config
    global dse
    global out_path
    global input_file
    global is_debug
    # Load the program (LIEF-based program loader).
    prog = CleLoader(os.environ['AFL_CUSTOM_INFO_PROGRAM'])
    # Process other configuration environment variables.
    argv = None
    try:
        foo = os.environ['AFL_DEBUG']
        is_debug = True
    except KeyError:
        pass
    try:
        foo = os.environ['AFL_CUSTOM_INFO_OUT']
        out_path = foo + '/../tritondse/queue'
    except KeyError:
        pass
    try:
        foo = os.environ['AFL_CUSTOM_INFO_PROGRAM_INPUT']
        input_file = foo
    except KeyError:
        pass
    try:
        argv_list = os.environ['AFL_CUSTOM_INFO_PROGRAM_ARGV']
        argv_tmp = [ os.environ['AFL_CUSTOM_INFO_PROGRAM'] ]
        argv_tmp += argv_list.split()
        argv = []
        # now check for @@
        for item in argv_tmp:
            if "@@" in item:
                input_file = out_path + '/../.input'
                argv.append(input_file)
            else:
                argv.append(item)
    except KeyError:
        pass
    # Create the output directory
    os.makedirs(out_path, exist_ok=True)
    # Debug
    if is_debug:
        print('DEBUG target: ' + os.environ['AFL_CUSTOM_INFO_PROGRAM'])
        if argv:
            print('DEBUG argv: ')
            print(argv)
        if input_file:
            print('DEBUG input_file: ' + input_file)
        print('DEBUG out_path: ' + out_path)
        print('')
    # Now set up TritonDSE
    config = Config(coverage_strategy = CoverageStrategy.PATH,
                    debug = is_debug,
                    pipe_stdout = is_debug,
                    pipe_stderr = is_debug,
                    execution_timeout = 1,
                    program_argv = argv,
                    smt_timeout= 50,
                    seed_format = SeedFormat.RAW)
    # Create an instance of the Symbolic Explorator
    dse = SymbolicExplorator(config, prog)
    # Add callbacks.
    dse.callback_manager.register_pre_execution_callback(pre_exec_hook)


#def fuzz(buf, add_buf, max_size):
#    return b""


def queue_new_entry(filename_new_queue, filename_orig_queue):
    global dse
    global cycle
    # Add seed to the worklist.
    with open(filename_new_queue, "rb") as file:
        seed = file.read()
    hash = hashlib.md5(seed).hexdigest()
    if hash not in hashes:
        hashes.add(hash)
        if is_debug:
            print("NEW FILE " + filename_new_queue + " hash " + hash + " count " + str(cycle))
            cycle += 1
        seed = Seed(seed)
        dse.add_input_seed(seed)
        # Start exploration!
        #dse.step()
        dse.explore()
    pass

def splice_optout():
    pass
