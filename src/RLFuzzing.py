#!/usr/bin/env python3


from argparse import ArgumentParser, ArgumentTypeError, Namespace
from typing import Optional, Tuple
import logging

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


def thompson_sample_step(a, b):
    return np.random.beta(a, b)


class RLFuzzing:
    def __init__(self,
                 use_correction_factor: Optional[bool] = False,
                 max_message_size: Optional[int] = 10000):
        logger.info('Initializing RLFuzzing. Use correction factor = %s',
                    use_correction_factor)
        self.mq_receiver = MessageQueue(1, IPC_CREAT,
                                        max_message_size=max_message_size)
        self.mq_sender = MessageQueue(2, IPC_CREAT,
                                      max_message_size=max_message_size)
        self.correction_factor = use_correction_factor
        self.map_size = None
        self.positive_reward = None
        self.negative_reward = None

    def compute_score(self):
        pos_reward = np.array(self.positive_reward, dtype=np.float64)
        neg_reward = np.array(self.negative_reward, dtype=np.float64)
        random_beta = thompson_sample_step(pos_reward, neg_reward)

        if self.correction_factor:
            rareness = ((pos_reward + neg_reward) /
                        (pos_reward**2 + pos_reward + neg_reward))**0.5
            score = random_beta * rareness
            return score
        return random_beta

    def start(self):
        while True:
            mtype, msg = self.receive()

            if mtype == INITIALIZATION_FLAG:
                self.map_size = int(msg[0])
                logger.info('map size = %d', self.map_size)
            elif mtype == UPDATE_SCORE:
                # Receive positive reward
                pos_reward = msg
                while len(pos_reward) < self.map_size:
                    _, msg = self.receive()
                    pos_reward = np.concatenate([pos_reward, msg])

                # Receive negative reward
                _, msg = self.receive()
                neg_reward = msg
                while len(neg_reward) < self.map_size:
                    _, msg = self.receive()
                    neg_reward = np.concatenate([neg_reward, msg])

                self.positive_reward = pos_reward[:self.map_size]
                self.negative_reward = neg_reward[:self.map_size]

                # Compute the best seed and its reward (to send back to AFL)
                score = self.compute_score()
                best_seed_id = np.argmax(score)
                reward = self.positive_reward[best_seed_id] + \
                        self.negative_reward[best_seed_id]
                logger.info('Best seed = %d, reward = %d', best_seed_id, reward)
                self.send(BEST_SEED, best_seed_id, reward)

    def receive(self) -> Tuple[int, np.ndarray]:
        logger.debug('Waiting for fuzzer message...')
        try:
            msg, mtype = self.mq_receiver.receive()
            logger.debug('Received `%s` message: %s', MESSAGE_TYPES[mtype], msg)
            return mtype, np.frombuffer(msg, dtype=np.uintc)
        except ExistentialError:
            logger.error('Message queue creation failed')
            raise

    def send(self, mtype: int, *msg: List[Any]) -> None:
        logger.debug('Sending `%s` message: %s', MESSAGE_TYPES[mtype], msg)
        ar = np.asarray(msg, dtype=np.uintc)
        try:
            self.mq_sender.send(ar.tobytes(order='C'), True, type=mtype)
        except ExistentialError:
            logger.error('Message queue creation failed')
            raise


def parse_args() -> Namespace:
    """Parse command-line arguments."""
    def log_level(val: str) -> int:
        """Ensure that an argument value is a valid log level."""
        numeric_level = getattr(logging, val.upper(), None)
        if not isinstance(numeric_level, int):
            raise ArgumentTypeError(f'{val!r} is not a valid log level')
        return numeric_level

    parser = ArgumentParser(description='RL-based fuzzing')
    parser.add_argument('--disable-correction-factor', required=False,
                        action='store_true', help='Disable correction factor')
    parser.add_argument('-l', '--log', default=logging.INFO, type=log_level,
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
    rl_fuzz = RLFuzzing(not args.disable_correction_factor)
    rl_fuzz.start()


if __name__ == "__main__":
    main()
