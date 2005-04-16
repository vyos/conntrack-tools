LINKOPTS=-ldl -lnfnetlink -lctnetlink -rdynamic
KERNELDIR=/lib/modules/$(shell uname -r)/build/include/
CFLAGS=-I${KERNELDIR} -Iinclude/ -g

default:
	${CC} -c ${CFLAGS} src/conntrack.c -o src/conntrack.o
	${CC} -c ${CFLAGS} src/libct.c -o src/libct.o
	${CC} ${LINKOPTS} src/conntrack.o src/libct.o -o conntrack
	${MAKE} -C extensions/

clean:
	rm -rf src/*.o conntrack
	${MAKE} clean -C extensions/

