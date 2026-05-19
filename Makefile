# NIL Makefile
# Supports: Linux (inotify), Termux/Android (polling), macOS (polling)

CC     ?= cc
CFLAGS  = -O2 -Wall -pthread
LDFLAGS = -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -lpcre2-8

# Detect platform
UNAME := $(shell uname -s)
IS_ANDROID := $(shell echo $$PREFIX | grep -c termux)

ifeq ($(IS_ANDROID),1)
    # Termux: use clang, explicit paths, no inotify
    CC      = clang
    CFLAGS += -I$(PREFIX)/include -D__ANDROID__
    LDFLAGS = -L$(PREFIX)/lib -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -lpcre2-8
else ifeq ($(UNAME),Linux)
    # Linux: inotify available
    CFLAGS += -D_GNU_SOURCE
else ifeq ($(UNAME),Darwin)
    # macOS: polling fallback, homebrew paths
    CFLAGS += -I/opt/homebrew/include -I/usr/local/include
    LDFLAGS = -L/opt/homebrew/lib -L/usr/local/lib \
              -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -lpcre2-8
endif

TARGET = nil
SRC    = nil.c

.PHONY: all clean install termux-deps

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/ 2>/dev/null || \
	install -m 755 $(TARGET) /usr/local/bin/

termux-deps:
	@echo "Run: bash setup_termux.sh"
