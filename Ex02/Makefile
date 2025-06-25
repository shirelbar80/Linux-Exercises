CC = gcc
LDFLAGS = -lpthread -lcrypto

# Build the final executable (not just program.o)
program: program.c mta_crypt.c mta_rand.c
	$(CC)  Queue.c mta_crypt.c mta_rand.c program.c -o program.o $(LDFLAGS)

clean:
	rm -f program.o