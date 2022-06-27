import sysv_ipc
import numpy as np
import struct

BUFF_SIZE = 16

try:
    mq = sysv_ipc.MessageQueue(1234, sysv_ipc.IPC_CREAT)

    while True:
        message, mtype = mq.receive()
        if mtype == 1:
            # afl_fsrv_map_size = struct.unpack("afl->fsrv.map_size", message)
            afl_fsrv_map_size = message.decode()
            print(f"afl->fsrv.map_size: {afl_fsrv_map_size}")

except sysv_ipc.ExistentialError:
    print("ERROR: message queue creation failed")