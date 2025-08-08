# CC = gcc
# # Added -lmta_crypt and -lmta_rand to link against preinstalled libraries instead of compiling the source files directly
# LDFLAGS = -lpthread -lcrypto -lmta_crypt -lmta_rand

# # Build the final executable
# program: program.c
# 	# Removed mta_crypt.c and mta_rand.c from compilation since they are now preinstalled libraries
# 	$(CC) Queue.c program.c -o program.o $(LDFLAGS)

# clean:
# 	rm -f program.o

#LATEST VERSION - MEKORI
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

# CC = gcc
# CFLAGS = -Wall -Wextra -std=c99 -fPIC
# LDFLAGS = -L. -lpthread -lcrypto -lmta_crypt -lmta_rand -lrt

# # Sources
# ENCRYPTER_SRC = encrypter.c linked_list.c
# DECRYPTER_SRC = decrypter.c

# # Binaries
# ENCRYPTER_BIN = encrypter
# DECRYPTER_BIN = decrypter

# # Shared libs
# SHARED_LIBS = libmta_crypt.so libmta_rand.so

# all: $(SHARED_LIBS) $(ENCRYPTER_BIN) $(DECRYPTER_BIN)

# # Build shared libraries
# libmta_crypt.so: mta_crypt.c mta_crypt.h
# 	$(CC) $(CFLAGS) -shared -o $@ mta_crypt.c

# libmta_rand.so: mta_rand.c mta_rand.h
# 	$(CC) $(CFLAGS) -shared -o $@ mta_rand.c

# # Build encrypter
# $(ENCRYPTER_BIN): $(ENCRYPTER_SRC)
# 	$(CC) $(CFLAGS) $(ENCRYPTER_SRC) -o $@ $(LDFLAGS)

# # Build decrypter
# $(DECRYPTER_BIN): $(DECRYPTER_SRC)
# 	$(CC) $(CFLAGS) $(DECRYPTER_SRC) -o $@ $(LDFLAGS)

# # Clean build artifacts
# clean:
# 	rm -f $(ENCRYPTER_BIN) $(DECRYPTER_BIN) $(SHARED_LIBS)

