CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = wake_scheduler

all: $(TARGET)

$(TARGET): wake_scheduler.c
	$(CC) $(CFLAGS) -o $(TARGET) wake_scheduler.c

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
