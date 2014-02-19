# $Id: Makefile.2,v 1.0 2013/11/21 22:30:10 hzheng Exp $ -Werror
PROG=	aed
OBJS=	aed.o
CFLAGS= -Wall 
LCFLAGS = -lcrypto -lbsd

all: ${PROG}

${PROG}: ${OBJS}
	@echo $@ depends on $?
	${CC} ${CFLAGS} ${LDFLAGS} ${OBJS} -o ${PROG} ${LCFLAGS}

clean:
	rm -f aed *.o *~

