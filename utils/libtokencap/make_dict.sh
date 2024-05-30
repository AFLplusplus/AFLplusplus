#!/bin/bash

LD_PRELOAD_PATH="/path/to/libtokencap.so"
AFL_TOKEN_FILE=${PWD}/temp_output.txt
AFL_DICT_FILE=$(basename ${target_output})
target_bin="/path/to/target/program"
target_output="/path/to/target/output"
timeout_sec="5"

{
touch $AFL_TOKEN_FILE
for i in $(find ${target_output} -type f -name "id*"); do
	LD_PRELOAD=${LD_PRELOAD_PATH} \
	timeout -s SIGKILL ${timeout_sec} \
	${target_bin} ${i}
done
} >${AFL_TOKEN_FILE}

sort -u ${AFL_TOKEN_FILE} >${AFL_DICT_FILE}.dict
