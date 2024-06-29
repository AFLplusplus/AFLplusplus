all:	custom_send_tcp.so

custom_send_tcp.so:
	$(CC) -Wno-unused-result -g -O3 -shared -fPIC -o custom_send_tcp.so -I../../include custom_send_tcp.c

clean:
	rm -f custom_send_tcp.so *.o *~ core
