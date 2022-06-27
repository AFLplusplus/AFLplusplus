import sysv_ipc
import numpy as np
import struct

BUFF_SIZE = 16

try:
    mq_reciever = sysv_ipc.MessageQueue(1, sysv_ipc.IPC_CREAT)

    while True:
        message, mtype = mq.receive()
        if mtype == 1:
            afl_fsrv_map_size = np.frombuffer(message, dtype=np.int8)
            # afl_fsrv_map_size = message.decode()
            print(f"afl->fsrv.map_size: {afl_fsrv_map_size}")

except sysv_ipc.ExistentialError:
    print("ERROR: message queue creation failed")

msg_npy = np.arange(BUFF_SIZE, dtype=np.uint8).reshape((2,BUFF_SIZE//2))

try:
    mq.send(msg_npy.tobytes(order='C'), True, type=TYPE_NUMPY)

except sysv_ipc.ExistentialError:
    print("ERROR: message queue creation failed")