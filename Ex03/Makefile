CC = gcc
# Added -lmta_crypt and -lmta_rand to link against preinstalled libraries instead of compiling the source files directly
LDFLAGS = -lpthread -lcrypto -lmta_crypt -lmta_rand

# Build the final executable
program: program.c
	# Removed mta_crypt.c and mta_rand.c from compilation since they are now preinstalled libraries
	$(CC) Queue.c program.c -o program.o $(LDFLAGS)

clean:
	rm -f program.o
