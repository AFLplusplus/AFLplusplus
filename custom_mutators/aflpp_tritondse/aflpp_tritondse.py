import sys
import os
import logging
import hashlib

from tritondse import CleLoader
from tritondse import CompositeData
from tritondse import Config
from tritondse import CoverageStrategy
from tritondse import ProcessState
from tritondse import Program
from tritondse import Seed
from tritondse import SeedFormat
from tritondse import SymbolicExecutor
from tritondse import SymbolicExplorator

is_debug = False
out_path = ""
input_file = None
prog = None
config = None
dse = None
cycle = 0
count = 0
finding = 0
hashes = set()
format = SeedFormat.RAW

def pre_exec_hook(se: SymbolicExecutor, state: ProcessState):
    global count
    global hashes
    global finding
    if se.seed.hash not in hashes:
        hashes.add(se.seed.hash)
        finding = 1
        filename = out_path + "/id:" + f"{count:06}" + "," + se.seed.hash
        if not os.path.exists(filename):
            if is_debug:
                print('Creating queue input ' + filename)
            with open(filename, 'wb') as file:
                if input_file:
                    file.write(se.seed.content.files[input_file])
                else:
                    file.write(se.seed.content)
                count += 1
    #if input_file:
    #    if is_debug:
    #        print('Writing to ' + input_file + ' the content: ' + str(se.seed.content))
    #    with open(input_file, 'wb') as file:
    #        file.write(se.seed.content)


#def rtn_open(se: SymbolicExecutor, pstate: ProcessState, pc):
#    """
#    The open behavior.
#    """
#    logging.debug('open hooked')
#
#    # Get arguments
#    arg0 = pstate.get_argument_value(0)  # const char *pathname
#    flags = pstate.get_argument_value(1)  # int flags
#    mode = pstate.get_argument_value(2)  # int mode
#    arg0s = pstate.memory.read_string(arg0)
#
#    # Concretize the whole path name
#    pstate.concretize_memory_bytes(arg0, len(arg0s)+1)  # Concretize the whole string + \0
#
#    # We use flags as concrete value
#    pstate.concretize_argument(1)
#
#    # Use the flags to open the file in the write mode.
#    mode = ""
#    if (flags & 0xFF) == 0x00:   # O_RDONLY
#        mode = "r"
#    elif (flags & 0xFF) == 0x01: # O_WRONLY
#        mode = "w"
#    elif (flags & 0xFF) == 0x02: # O_RDWR
#        mode = "r+"
#
#    if (flags & 0x0100): # O_CREAT
#        mode += "x"
#    if (flags & 0x0200): # O_APPEND
#        mode = "a"  # replace completely value
#
#    if se.seed.is_file_defined(arg0s) and "r" in mode:  # input file and opened in reading
#        logging.info(f"opening an input file: {arg0s}")
#        # Program is opening an input
#        data = se.seed.get_file_input(arg0s)
#        filedesc = pstate.create_file_descriptor(arg0s, io.BytesIO(data))
#        fd = filedesc.id
#    else:
#        # Try to open it as a regular file
#        try:
#            fd = open(arg0s, mode)  # use the mode here
#            filedesc = pstate.create_file_descriptor(arg0s, fd)
#            fd = filedesc.id
#        except Exception as e:
#            logging.debug(f"Failed to open {arg0s} {e}")
#            fd = pstate.minus_one
#
#    pstate.write_register("rax", fd)  # write the return value
#    pstate.cpu.program_counter = pstate.pop_stack_value()  # pop the return value
#    se.skip_instruction()  # skip the current instruction so that the engine go straight fetching the next instruction


def init(seed):
    global config
    global dse
    global format
    global input_file
    global is_debug
    global out_path
    global prog
    # Load the program (LIEF-based program loader).
    prog = CleLoader(os.environ['AFL_CUSTOM_INFO_PROGRAM'])
    # Process other configuration environment variables.
    argv = None
    try:
        foo = os.environ['AFL_DEBUG']
        is_debug = True
    except KeyError:
        pass
    if is_debug:
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.CRITICAL)
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
    if input_file:
        format = SeedFormat.COMPOSITE
    # Now set up TritonDSE
    config = Config(coverage_strategy = CoverageStrategy.PATH,
    #                debug = is_debug,
                    pipe_stdout = is_debug,
                    pipe_stderr = is_debug,
                    execution_timeout = 1,
                    program_argv = argv,
                    smt_timeout= 50,
                    seed_format = format)
    # Create an instance of the Symbolic Explorator
    dse = SymbolicExplorator(config, prog)
    # Add callbacks.
    dse.callback_manager.register_pre_execution_callback(pre_exec_hook)
    #dse.callback_manager.register_function_callback("open", rtn_open)


def fuzz(buf, add_buf, max_size):
    global finding
    finding = 1
    while finding == 1:
      finding = 0
      dse.step()
    return b""


def queue_new_entry(filename_new_queue, filename_orig_queue):
    global cycle
    global dse
    # Add seed to the worklist.
    with open(filename_new_queue, "rb") as file:
        data = file.read()
    hash = hashlib.md5(data).hexdigest()
    if hash not in hashes:
        hashes.add(hash)
        if is_debug:
            print("NEW FILE " + filename_new_queue + " hash " + hash + " count " + str(cycle))
            cycle += 1
        if input_file:
            seed = Seed(CompositeData(files={"stdin": b"", # nothing on stdin
                                  input_file: data}))
        else:
            seed = Seed(data)
        dse.add_input_seed(seed)
        # Start exploration!
        #dse.step()
        #dse.explore()
    pass


# we simulate just doing one single fuzz in the custom mutator
def fuzz_count(buf):
    return 1


def splice_optout():
    pass
