CC ?= clang
CFLAGS = -std=c99 -O3 -Wall -Wextra -pedantic

LIBRARY=libnss_nfs4.so.2

all: ${LIBRARY}

${LIBRARY}: CFLAGS += -shared -fPIC
${LIBRARY}: nfs4.c
	${CC} ${CFLAGS} -Wl,-soname,${LIBRARY}\
		-o ${LIBRARY} $^

clean:
	${RM} *.so* *.o
install:
	cp ${LIBRARY} /lib
	cp ${LIBRARY} /usr/lib

.PHONY: all clean install
