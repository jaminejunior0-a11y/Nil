# NIL v4.0 Makefile
# Supports: Linux, Termux (Android)

CC     ?= gcc
CFLAGS  = -O2 -Wall -pthread
LDFLAGS = -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -lpcre2-8

# Detect Termux and add its include/lib paths
ifeq ($(shell echo $$PREFIX),/data/data/com.termux/files/usr)
    CFLAGS  += -I$(PREFIX)/include
    LDFLAGS += -L$(PREFIX)/lib
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
	@echo "Run setup_termux.sh instead — json-c must be built from source."
	@echo "  bash setup_termux.sh"
