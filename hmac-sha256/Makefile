CC = clang
CFLAGS= -g # -O3 -pedantic -Wall -Wextra -std=c99
CBMC = cbmc
TARGET = hmac-sha256

.PHONY: clean verify

$(TARGET).o: hmac-sha256.c sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

basic_test: hmac-sha256.c sha256.h
	$(CC) $(CFLAGS) -o $(TARGET) -DSHA256_SELF_TEST__ $<

performance_test: hmac-sha256.c sha256.h
	$(CC) $(CFLAGS) -o $(TARGET) -DSHA256_PERF_TEST__ $<

all: basic_test performance_test $(TARGET)

clean:
	rm -f $(TARGET) *.o
