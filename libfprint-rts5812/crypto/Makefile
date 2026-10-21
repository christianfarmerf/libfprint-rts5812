# Offline test for the RTS5812 frame crypto. Requires nettle (>= 3.6) dev headers.
#   Fedora/RHEL : sudo dnf install nettle-devel
#   Debian/Ubuntu: sudo apt install nettle-dev
#
#   make           # build ./test_decode
#   make check     # build + run against ../../frame.bin
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
PKG     := $(shell pkg-config --cflags --libs nettle 2>/dev/null || echo -lnettle)

test_decode: test_decode.c rts5812_crypto.c rts5812_crypto.h
	$(CC) $(CFLAGS) -o $@ test_decode.c rts5812_crypto.c $(PKG)

.PHONY: check clean
check: test_decode
	./test_decode ../../frame.bin ../../frame.bin.blob out.pgm

clean:
	rm -f test_decode out.pgm
