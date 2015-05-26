OBJS =
OBJS += main.o
OBJS += tcpstream.o

DEF = 
DEF += -O3 
DEF += --std=c99 
DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 
DEF += -g

LIBS =
LIBS += -lm

%.o: %.c
	gcc $(DEF) -c -o $@ -g $<

all: $(OBJS) 
	gcc -g -o pcap_flows $(OBJS)  $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f pcap_flows

