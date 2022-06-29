import sysv_ipc
import numpy as np
import struct

FUZZING_LOOP = 1
UPDATE_BITMAP = 2


class RLFuzzing:
    def __init__(self,max_message_size=10000):
        self.mq_reciever = sysv_ipc.MessageQueue(1, sysv_ipc.IPC_CREAT, max_message_size=max_message_size)
        self.mq_sender = sysv_ipc.MessageQueue(2, sysv_ipc.IPC_CREAT, max_message_size=max_message_size)
        self.step_exec_map = None
        return

    def recieve_messages(self, BUFF_SIZE_RECIEVER=1024):
        try:
            

            message, mtype = self.mq_reciever.receive()

            if mtype == FUZZING_LOOP:
                afl_fsrv_map_size = np.frombuffer(message, dtype=np.double)
                print(f"afl->fsrv.map_size: {afl_fsrv_map_size}")
                print(f"mtype: {mtype}")
                self.send_messenges(mtype)

            elif mtype == UPDATE_BITMAP:
                message_numpy_array = np.frombuffer(message, dtype=np.uintc)
                map_size = message_numpy_array[0]
                trace_bits = message_numpy_array[1:map_size]
                while len(trace_bits) < map_size:
                    message_numpy_array = np.frombuffer(message, dtype=np.uintc)
                    trace_bits = np.concatenate([trace_bits, message_numpy_array[1:map_size]])
                trace_bits = trace_bits[:map_size]

                if self.step_exec_map is None:
                    self.step_exec_map = np.zeros(map_size)

                self.step_exec_map[trace_bits != 0] += 1
                print(f"afl->fsrv.map_size: {map_size}")
                print(f"afl->fsrv.trace_bits: {trace_bits}")
                print(f"len(trace_bits): {len(trace_bits)}")
                print(f"self.step_exec_map: {self.step_exec_map}")
                print(f"mtype: {mtype}")
                # self.send_messenges(mtype)

        except sysv_ipc.ExistentialError:
            print("ERROR: message queue creation failed")

    def send_messenges(self, mtype, BUFF_SIZE_SENDER=1024):
        if mtype == FUZZING_LOOP:
            msg_npy = np.arange(BUFF_SIZE_SENDER, dtype=np.double).reshape((2,BUFF_SIZE_SENDER//2))
        # elif mtype == UPDATE_BITMAP:
        #     msg_npy = np.arange(BUFF_SIZE_SENDER, dtype=np.uint8).reshape((2,BUFF_SIZE_SENDER//2))

        try:
            
            self.mq_sender.send(msg_npy.tobytes(order='C'), False, type=mtype)

        except sysv_ipc.ExistentialError:
            print("ERROR: message queue creation failed")



if __name__ == "__main__":
    RLF = RLFuzzing()
    while True:
        RLF.recieve_messages()

