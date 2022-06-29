from jax import numpy as jnp
from jax import random
from jax import jit, lax

import numpy as np
import sysv_ipc
# import struct

FUZZING_LOOP = 1
UPDATE_BITMAP = 2


class RLFuzzing:
    def __init__(self,max_message_size=10000):
        self.map_size = None

        self.mq_reciever = sysv_ipc.MessageQueue(1, sysv_ipc.IPC_CREAT, max_message_size=max_message_size)
        self.mq_sender = sysv_ipc.MessageQueue(2, sysv_ipc.IPC_CREAT, max_message_size=max_message_size)

        self.step_exec_map = None     # Positive Reward
        self.negative_reward = None

        self.key = random.PRNGKey(0)
        return

    @jit
    def thompson_sample_step(self, key, number_of_positive_rewards, number_of_negative_rewards):
        a = number_of_positive_rewards + 1
        b = number_of_negative_rewards + 1

        random_beta = random.beta(key, a, b)
        return random_beta


    def compute_score(self, key):
        pr = jnp.array(self.step_exec_map, dtype=float64)
        nr = jnp.array(self.negative_reward, dtype=float64)
        random_beta = self.thompson_sample_step(key, pr, nr)
        rareness = pr**2 / nr
        score = random_beta / rareness
        return np.array(score)

    def recieve_messages(self, BUFF_SIZE_RECIEVER=1024):
        try:
            

            message, mtype = self.mq_reciever.receive()

            if mtype == FUZZING_LOOP:
                self.map_size = np.frombuffer(message, dtype=np.double)[0]
                print(f"self.map_size: {self.map_size}")
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

                if self.negative_reward is None:
                    self.negative_reward = np.zeros(map_size)

                self.step_exec_map[trace_bits != 0] += 1
                self.negative_reward[trace_bits == 0] += 1

                print(f"afl->fsrv.map_size: {map_size}")
                print(f"afl->fsrv.trace_bits: {trace_bits}")
                print(f"len(trace_bits): {len(trace_bits)}")
                print(f"self.step_exec_map: {self.step_exec_map}")
                print(f"self.negative_reward: {self.negative_reward}")
                print(f"mtype: {mtype}")
                # self.send_messenges(mtype)

        except sysv_ipc.ExistentialError:
            print("ERROR: message queue creation failed")

    def send_messenges(self, mtype, BUFF_SIZE_SENDER=1024):
        if mtype == FUZZING_LOOP:
            self.key, k = random.split(self.key)
            score = self.compute_score(k)

            while len(score):
                msg_npy = score[:BUFF_SIZE_SENDER].reshape((2,BUFF_SIZE_SENDER//2))
                score = score[BUFF_SIZE_SENDER:]
                try:
                    self.mq_sender.send(msg_npy.tobytes(order='C'), False, type=mtype)
                except sysv_ipc.ExistentialError:
                    print("ERROR: message queue creation failed")



        # elif mtype == UPDATE_BITMAP:
        #     msg_npy = np.arange(BUFF_SIZE_SENDER, dtype=np.uint8).reshape((2,BUFF_SIZE_SENDER//2))

        # try:
            
        #     self.mq_sender.send(msg_npy.tobytes(order='C'), False, type=mtype)

        # except sysv_ipc.ExistentialError:
        #     print("ERROR: message queue creation failed")



if __name__ == "__main__":
    RLF = RLFuzzing()
    while True:
        RLF.recieve_messages()

