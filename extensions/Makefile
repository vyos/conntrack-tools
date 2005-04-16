CC=gcc

all:
	${CC} -fPIC -Wall -g -c libct_proto_tcp.c
	${CC} -g -shared -Wl,-soname,libct_proto_tcp.so.0 -o libct_proto_tcp.so.0.0 libct_proto_tcp.o -lc
	ln -sf libct_proto_tcp.so.0.0 libct_proto_tcp.so

	${CC} -fPIC -Wall -g -c libct_proto_udp.c
	${CC} -g -shared -Wl,-soname,libct_proto_udp.so.0 -o libct_proto_udp.so.0.0 libct_proto_udp.o -lc
	ln -sf libct_proto_udp.so.0.0 libct_proto_udp.so
clean:
	rm -rf *.so *.so.* *.o
