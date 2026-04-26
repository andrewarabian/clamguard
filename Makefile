CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Wpedantic -std=c11 -D_GNU_SOURCE
LDFLAGS = -pthread
TARGET  = clamguard
SRC     = clamguard.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 0755 -o root -g root $(TARGET) /usr/local/bin/$(TARGET)
