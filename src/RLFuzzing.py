from jax import numpy as jnp
from jax import random
# from jax import jit, lax

import numpy as np
import sysv_ipc
# import struct

INITALIZATION_FLAG = 1
UPDATE_SCORE = 2


class RLFuzzing:
    def __init__(self,max_message_size=10000):
        self.map_size = None

        self.mq_reciever = sysv_ipc.MessageQueue(1, sysv_ipc.IPC_CREAT, max_message_size=max_message_size)
        self.mq_sender = sysv_ipc.MessageQueue(2, sysv_ipc.IPC_CREAT, max_message_size=max_message_size)

        self.positive_reward = None
        self.negative_reward = None

        self.key = random.PRNGKey(0)
        return

    # @jit
    def thompson_sample_step(self, key, number_of_positive_rewards, number_of_negative_rewards):
        a = number_of_positive_rewards + 1
        b = number_of_negative_rewards + 1

        random_beta = random.beta(key, a, b)
        # random_beta = np.random.beta(a,b)
        return random_beta


    def compute_score(self, key):
        pr = np.array(self.positive_reward, dtype=np.float64)
        nr = np.array(self.negative_reward, dtype=np.float64)
        random_beta = self.thompson_sample_step(key, pr, nr)
        rareness = (pr**2) / (pr+nr+1)
        score = (np.array(random_beta, dtype=np.float64) / (1+rareness))**0.5
        return np.array(score)

    def recieve_messages(self, BUFF_SIZE_RECIEVER=1024):
        try:
            message, mtype = self.mq_reciever.receive()

            if mtype == INITALIZATION_FLAG:
                self.map_size = int(np.frombuffer(message, dtype=np.uint)[0])

            elif mtype == UPDATE_SCORE:
                message_numpy_array = np.frombuffer(message, dtype=np.uint)
                positive_reward = message_numpy_array
                while len(positive_reward) < self.map_size:
                    message_numpy_array = np.frombuffer(message, dtype=np.uint)
                    positive_reward = np.concatenate([positive_reward, message_numpy_array])

                message_numpy_array = np.frombuffer(message, dtype=np.uintc)
                negative_reward = message_numpy_array
                while len(negative_reward) < self.map_size:
                    message_numpy_array = np.frombuffer(message, dtype=np.uint)
                    negative_reward = np.concatenate([negative_reward, message_numpy_array])

                self.positive_reward = positive_reward[:self.map_size]
                self.negative_reward = negative_reward[:self.map_size]
                self.send_messenges(mtype)


            # elif mtype == UPDATE_BITMAP:
            #     message_numpy_array = np.frombuffer(message, dtype=np.uintc)
            #     map_size = message_numpy_array[0]
            #     trace_bits = message_numpy_array[1:map_size]
            #     while len(trace_bits) < map_size:
            #         message_numpy_array = np.frombuffer(message, dtype=np.uintc)
            #         trace_bits = np.concatenate([trace_bits, message_numpy_array[1:map_size]])
            #     trace_bits = trace_bits[:map_size]

            #     if self.positive_reward is None:
            #         self.positive_reward = np.zeros(map_size)

            #     if self.negative_reward is None:
            #         self.negative_reward = np.zeros(map_size)

            #     self.positive_reward[trace_bits != 0] += 1
            #     self.negative_reward[trace_bits == 0] += 1

        except sysv_ipc.ExistentialError:
            print("ERROR: message queue creation failed")

    def send_messenges(self, mtype, BUFF_SIZE_SENDER=1024):
        if mtype == UPDATE_SCORE:
            self.key, k = random.split(self.key)
            print(f'self.map_size: {self.map_size}')
            print(f'self.positive_reward: {self.positive_reward}, len: {len(self.positive_reward)}')
            print(f'self.negative_reward: {self.negative_reward}, len: {len(self.negative_reward)}')
            score = self.compute_score(k)
            best_seed_id = np.argmax(score)
            msg_npy = np.zeros(BUFF_SIZE_SENDER)
            msg_npy[0] = best_seed_id
            msg_npy[1] = self.positive_reward[best_seed_id] + self.negative_reward[best_seed_id]
            msg_npy = np.array(msg_npy, dtype=np.uint).reshape((2,BUFF_SIZE_SENDER//2))
            try:
                self.mq_sender.send(msg_npy.tobytes(order='C'), True, type=mtype)
            except sysv_ipc.ExistentialError:
                print("ERROR: message queue creation failed")


            # index = 0
            # while index < self.map_size:
            #     msg_npy = np.zeros(BUFF_SIZE_SENDER)
            #     msg_npy[:len(score[index:index+BUFF_SIZE_SENDER])]= score[index:index+BUFF_SIZE_SENDER]
            #     msg_npy = np.array(msg_npy, dtype=np.float64).reshape((2,BUFF_SIZE_SENDER//2))
            #     index += BUFF_SIZE_SENDER
            #     try:
            #         self.mq_sender.send(msg_npy.tobytes(order='C'), True, type=mtype)
            #     except sysv_ipc.ExistentialError:
            #         print("ERROR: message queue creation failed")


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

