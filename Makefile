NAME := $(notdir $(shell pwd))
CC = gcc
CFLAGS = -O2 -Wall -pthread -Iinclude `pkg-config --cflags libpcap libcjson zlib`
LDFLAGS = `pkg-config --libs libpcap libcjson zlib`
OBJDIR := obj
SRCDIR := src
BINDIR := bin
DIRS := $(OBJDIR) $(BINDIR)
BIN := $(BINDIR)/$(NAME)
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(wildcard $(SRCDIR)/*.c))
#SRCS = src/main.c src/collector.c src/ipacct.c src/pcap_if.c src/poller.c src/storage.c src/control.c
#OBJS = $(SRCS:.c=.o)
MKDIR_P := mkdir -p

.PHONY: all

all: $(BIN)

#netacct: $(OBJS)
#	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(BIN): ${DIRS} $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(BIN) $(OBJS)

${DIRS}:
	$(MKDIR_P) $(DIRS)
