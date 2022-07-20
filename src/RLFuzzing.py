#!/usr/bin/env python3


from argparse import ArgumentParser, ArgumentTypeError, Namespace
from typing import Optional
import logging

from jax import random
import numpy as np
from sysv_ipc import ExistentialError, MessageQueue, IPC_CREAT


# Keep this in sync with the message types in rl-py.h
INITIALIZATION_FLAG = 1
UPDATE_SCORE = 2
BEST_SEED = 3

# Map message types to a string descriptor
MESSAGE_TYPES = {
    INITIALIZATION_FLAG: 'initialization flag',
    UPDATE_SCORE: 'update score',
    BEST_SEED: 'best seed'
}


# Logging
FORMATTER = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger()

def thompson_sample_step(key, a, b):
    return random.beta(key, a, b)


class RLFuzzing:
    def __init__(self,
                 use_correction_factor: Optional[bool] = False,
                 max_message_size: Optional[int] = 10000):
        self.mq_reciever = MessageQueue(1, IPC_CREAT,
                                        max_message_size=max_message_size)
        self.mq_sender = MessageQueue(2, IPC_CREAT,
                                      max_message_size=max_message_size)
        self.correction_factor = use_correction_factor
        self.map_size = None
        self.positive_reward = None
        self.negative_reward = None
        self.key = random.PRNGKey(0)

    def compute_score(self, key):
        pos_reward = np.array(self.positive_reward, dtype=np.float64)
        neg_reward = np.array(self.negative_reward, dtype=np.float64)
        random_beta = thompson_sample_step(key, pos_reward, neg_reward)
#         rareness = (pr**2) / (pr+nr+1)
#         score = (np.array(random_beta, dtype=np.float64) / (1+rareness))**0.5
        if self.correction_factor:
            rareness = ((pos_reward + neg_reward) /
                        (pos_reward**2 + pos_reward + neg_reward))**0.5
            score = np.array(random_beta, dtype=np.float64) * rareness
            return score
        return np.array(random_beta, dtype=np.float64)

    def receive(self, buff_size_receiver=1024):
        logger.debug('Waiting for fuzzer message...')
        try:
            message, mtype = self.mq_reciever.receive()
            logger.debug('Received `%s` message', MESSAGE_TYPES[mtype])

            if mtype == INITIALIZATION_FLAG:
                self.map_size = int(np.frombuffer(message, dtype=np.uintc)[0])
                logger.debug('map size = %d', self.map_size)
            elif mtype == UPDATE_SCORE:
                message_numpy_array = np.frombuffer(message, dtype=np.uintc)
                pos_reward = message_numpy_array
                while len(pos_reward) < self.map_size:
                    message, mtype = self.mq_reciever.receive()
                    message_numpy_array = np.frombuffer(message, dtype=np.uintc)
                    pos_reward = np.concatenate([pos_reward, message_numpy_array])

                message, mtype = self.mq_reciever.receive()
                message_numpy_array = np.frombuffer(message, dtype=np.uintc)
                neg_reward = message_numpy_array
                while len(neg_reward) < self.map_size:
                    message, mtype = self.mq_reciever.receive()
                    message_numpy_array = np.frombuffer(message, dtype=np.uintc)
                    neg_reward = np.concatenate([neg_reward, message_numpy_array])

                self.positive_reward = pos_reward[:self.map_size]
                self.negative_reward = neg_reward[:self.map_size]

                self.send(BEST_SEED)
        except ExistentialError:
            logger.error('Message queue creation failed')

    def send(self, mtype, buff_size_sender=1024):
        logger.debug('Sending `%s` message', MESSAGE_TYPES[mtype])
        if mtype == BEST_SEED:
            self.key, k = random.split(self.key)
            score = self.compute_score(k)
            best_seed_id = np.argmax(score)
            msg_npy = np.zeros(2, dtype=np.uintc)
            msg_npy[0] = best_seed_id
            msg_npy[1] = self.positive_reward[best_seed_id] + \
                    self.negative_reward[best_seed_id]
            logger.debug('Best seed = %d, reward = %d', msg_npy[0], msg_npy[1])
            try:
                self.mq_sender.send(msg_npy.tobytes(order='C'), True, type=mtype)
            except ExistentialError:
                logger.error('Message queue creation failed')


def parse_args() -> Namespace:
    """Parse command-line arguments."""
    def log_level(val: str) -> int:
        """Ensure that an argument value is a valid log level."""
        numeric_level = getattr(logging, val.upper(), None)
        if not isinstance(numeric_level, int):
            raise ArgumentTypeError(f'{val!r} is not a valid log level')
        return numeric_level

    parser = ArgumentParser(description='RL-based fuzzing')
    parser.add_argument('-c', '--correction-factor', required=False,
                        action='store_true', help='Use correction factor')
    parser.add_argument('-l', '--log', default=logging.WARN, type=log_level,
                        help='Logging level')

    return parser.parse_args()


def main():
    """Main function."""
    args = parse_args()

    # Configure logger
    handler = logging.StreamHandler()
    handler.setFormatter(FORMATTER)
    logger.addHandler(handler)
    logger.setLevel(args.log)

    # Start the RL
    rl_fuzz = RLFuzzing(args.correction_factor)
    while True:
        rl_fuzz.receive()


if __name__ == "__main__":
    main()
