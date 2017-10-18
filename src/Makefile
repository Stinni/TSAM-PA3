CC = gcc
CFLAGS = -std=gnu11 -O2 -g -Wall -Wextra -Wformat=2 $(shell pkg-config glib-2.0 openssl --cflags --libs)

.DEFAULT: all
.PHONY: all
all: httpd

httpd:
	$(CC) $(CFLAGS) httpd.c -o $@ -lm

clean:
	rm -f *.o *~

distclean: clean
	rm -f httpd
