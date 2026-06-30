NAME := netacct
CC ?= gcc
PKG_CFLAGS := $(shell pkg-config --cflags libpcap libcjson zlib 2>/dev/null)
PKG_LIBS := $(shell pkg-config --libs libpcap libcjson zlib 2>/dev/null)
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11 -pthread -Iinclude $(PKG_CFLAGS)
LDFLAGS ?= $(PKG_LIBS) -pthread
OBJDIR := obj
SRCDIR := src
BINDIR := bin
BIN := $(BINDIR)/$(NAME)
SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
LOCALSTATEDIR ?= /var/lib
SYSTEMDDIR ?= /etc/systemd/system

.PHONY: all clean install uninstall check-deps

all: check-deps $(BIN)

check-deps:
	@pkg-config --exists libpcap libcjson zlib || \
	 (echo "Missing dependencies. On Debian/Raspberry Pi OS: sudo apt install build-essential pkg-config libpcap-dev libcjson-dev zlib1g-dev" >&2; exit 1)

$(BIN): $(OBJS) | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c include/netacct.h | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ -c $<

$(OBJDIR) $(BINDIR):
	mkdir -p $@

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/netacct
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -m 0644 etc/netacct.conf.example $(DESTDIR)$(SYSCONFDIR)/netacct.conf
	install -d $(DESTDIR)$(LOCALSTATEDIR)/netacct
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install -m 0644 systemd/netacct.service $(DESTDIR)$(SYSTEMDDIR)/netacct.service

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/netacct
	rm -f $(DESTDIR)$(SYSTEMDDIR)/netacct.service

clean:
	rm -rf $(OBJDIR) $(BINDIR)
