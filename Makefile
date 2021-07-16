OBJS =
OBJS += main.o
OBJS += flow.o
OBJS += tcpevent.o
OBJS += sha1.o
OBJS += output.o
OBJS += fProfile.o
OBJS += histogram.o

DEF = 
DEF += -O3 
DEF += --std=c99 
DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 
DEF += -g

LIBS =
LIBS += -lm
LIBS += -lpthread
LIBS += -lrt

%.o: %.c
	gcc $(DEF) -c -o $@ -g $<

all: $(OBJS) 
	gcc -g -o pcap2json $(OBJS)  $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f pcap2json 

