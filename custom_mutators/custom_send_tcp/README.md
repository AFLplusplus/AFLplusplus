# Send testcases via TCP custom mutator

This custom mutator sends the fuzzing testcases via TCP.

`AFL_CUSTOM_MUTATOR_LATE_SEND` - MUST be set!
`CUSTOM_SEND_IP` - the IP address to send to (basically only 127.0.0.1 makes sense)
`CUSTOM_SEND_PORT` - the TCP port to send to
`CUSTOM_SEND_READ` - if the custom mutator should wait for a reply from the target

Example:
```
CUSTOM_SEND_IP=127.0.0.1 CUSTOM_SEND_PORT=8000 CUSTOM_SEND_READ=1 AFL_CUSTOM_MUTATOR_LATE_SEND=1 AFL_CUSTOM_MUTATOR_LIBRARY=custom_send_tcp.so ./afl-fuzz ...
```
