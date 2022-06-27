import sysv_ipc
import numpy as np
import struct

BUFF_SIZE = 64

try:
	mq = sysv_ipc.MessageQueue(1234, sysv_ipc.IPC_CREAT)

	while True:
		message, mtype = mq.receive()
		if mtype == 1:
			sched_exec_map = struct.unpack("sched->exec_map", message)
			print(f"Scheduler exec_map: {sched_exec_map}")
			