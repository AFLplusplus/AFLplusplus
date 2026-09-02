CFLAGS ?= -Wall -Wextra -O2 -g
INC = -I ../../custom_mutators/state_records

all: pool-hit-rate

pool-hit-rate: pool-hit-rate.c ../../custom_mutators/state_records/state_records.h
	$(CC) $(CFLAGS) $(INC) pool-hit-rate.c -o pool-hit-rate

clean:
	rm -f pool-hit-rate

.PHONY: all clean
