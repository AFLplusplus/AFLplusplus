import sysv_ipc
import numpy as np
import struct

BUFF_SIZE = 64

try:
    mq = sysv_ipc.MessageQueue(1234, sysv_ipc.IPC_CREAT)

    while True:
        print('here')
        message, mtype = mq.receive()
        print(mtype)
        if mtype == 1:
            afl_fsrv_map_size = struct.unpack("afl->fsrv.map_size", message)
            print(f"afl->fsrv.map_size: {afl_fsrv_map_size}")

except sysv_ipc.ExistentialError:
    print("ERROR: message queue creation failed")