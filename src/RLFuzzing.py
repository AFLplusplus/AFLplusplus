import sysv_ipc
import numpy as np
import struct


class RLFuzzing:
    def __init__(self):
        return

    def recieve_messages(self, BUFF_SIZE_RECIEVER=32):
        try:
            mq_reciever = sysv_ipc.MessageQueue(1, sysv_ipc.IPC_CREAT)

            message, mtype = mq_reciever.receive()

            if mtype == 1:
                afl_fsrv_map_size = np.frombuffer(message, dtype=np.double)
                # afl_fsrv_map_size = message.decode()
                print(f"afl->fsrv.map_size: {afl_fsrv_map_size}")
                print(f"mtype: {mtype}")
                self.send_messenges(mtype)
            elif mtype == 2:
                afl_fsrv_map_size = np.frombuffer(message, dtype=np.uint8)
                # afl_fsrv_map_size = message.decode()
                print(f"afl->fsrv.map_size: {afl_fsrv_map_size}")
                print(f"mtype: {mtype}")
                self.send_messenges(mtype)

        except sysv_ipc.ExistentialError:
            print("ERROR: message queue creation failed")

    def send_messenges(self, mtype, BUFF_SIZE_SENDER=64):
        if mtype == 1:
            msg_npy = np.arange(BUFF_SIZE_SENDER, dtype=np.double).reshape((2,BUFF_SIZE_SENDER//2))
        elif mtype == 2:
            msg_npy = np.arange(BUFF_SIZE_SENDER, dtype=np.uint8).reshape((2,BUFF_SIZE_SENDER//2))

        try:
            mq_sender = sysv_ipc.MessageQueue(2, sysv_ipc.IPC_CREAT)
            mq_sender.send(msg_npy.tobytes(order='C'), True, type=mtype)

        except sysv_ipc.ExistentialError:
            print("ERROR: message queue creation failed")



if __name__ == "__main__":
    RLF = RLFuzzing()
    while True:
        RLF.recieve_messages()

