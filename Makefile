CC = gcc
CFLAGS = -O2 -Wall -pthread -Iinclude `pkg-config --cflags libpcap`
LDFLAGS = `pkg-config --libs libpcap`
SRCS = src/main.c src/ipacct.c src/pcap_if.c src/poller.c src/storage.c
OBJS = $(SRCS:.c=.o)

all: netacct

netacct: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f netacct src/*.o

