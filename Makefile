CC ?= clang
CFLAGS = -std=c99 -O3 -Wall -Wextra -pedantic

LIBRARY=libnss_nfs4.so.2

all: ${LIBRARY}

${LIBRARY}: CFLAGS += -shared -fPIC -pthread
${LIBRARY}: nfs4.c
	${CC} ${CFLAGS} -Wl,-soname,${LIBRARY}\
		-o ${LIBRARY} -pthread $^

clean:
	${RM} *.so* *.o
install:
	cp ${LIBRARY} /lib
	cp ${LIBRARY} /usr/lib

fpm_centos: ${LIBRARY}
	install -d release/lib64
	install -m 755 ${LIBRARY} release/lib64

.PHONY: all clean install
