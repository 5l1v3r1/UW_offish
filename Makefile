TARGETS	= UWoffish
CFLAGSF	= -W -Wall
CFLAGS	= -g
LDFLAGSF=
CC	= cc
RM	= rm -f


all: $(TARGETS)

UWoffish_OBJS= UWoffish.o
UWoffish_CFLAGS=$(CFLAGSF) $(CFLAGS)
UWoffish: $(UWoffish_OBJS)
	$(CC) $(LDFLAGSF) $(LDFLAGS) -o UWoffish $(UWoffish_OBJS)

UWoffish.o: UWoffish.c
	$(CC) $(UWoffish_CFLAGS) -c UWoffish.c

clean:
	$(RM) $(UWoffish_OBJS)

distclean: clean
	$(RM) $(TARGETS)
