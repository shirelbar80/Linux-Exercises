CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpthread -lcrypto
OBJS = program.o mta_crypt.o mta_rand.o

all: program

program: $(OBJS)
	$(CC) $(OBJS) -o program $(LDFLAGS)

program.o: program.c
	$(CC) $(CFLAGS) -c program.c

mta_crypt.o: mta_crypt.c
	$(CC) $(CFLAGS) -c mta_crypt.c

mta_rand.o: mta_rand.c
	$(CC) $(CFLAGS) -c mta_rand.c

clean:
	rm -f $(OBJS) program
