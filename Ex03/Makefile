# CC = gcc
# # Added -lmta_crypt and -lmta_rand to link against preinstalled libraries instead of compiling the source files directly
# LDFLAGS = -lpthread -lcrypto -lmta_crypt -lmta_rand

# # Build the final executable
# program: program.c
# 	# Removed mta_crypt.c and mta_rand.c from compilation since they are now preinstalled libraries
# 	$(CC) Queue.c program.c -o program.o $(LDFLAGS)

# clean:
# 	rm -f program.o


CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lpthread -lcrypto -lmta_crypt -lmta_rand

# קבצים לקומפילציה
ENCRYPTER_SRC = encrypter.c linked_list.c
DECRYPTER_SRC = decrypter.c

# קבצי ההפעלה
ENCRYPTER_BIN = encrypter
DECRYPTER_BIN = decrypter

all: $(ENCRYPTER_BIN) $(DECRYPTER_BIN)

$(ENCRYPTER_BIN): $(ENCRYPTER_SRC)
	$(CC) $(CFLAGS) $(ENCRYPTER_SRC) -o $(ENCRYPTER_BIN) $(LDFLAGS)

$(DECRYPTER_BIN): $(DECRYPTER_SRC)
	$(CC) $(CFLAGS) $(DECRYPTER_SRC) -o $(DECRYPTER_BIN) $(LDFLAGS)

clean:
	rm -f $(ENCRYPTER_BIN) $(DECRYPTER_BIN)