#!/bin/bash

# Usage check
if [ $# -ne 1 ]; then
    echo "Usage: $0 <number_of_decrypters>"
    exit 1
fi

NUM_DECRYPTERS=$1

# Relative path for logs
LOG_DIR="./var/log"

# Create folder if missing
mkdir -p "$LOG_DIR"

# Run encrypter first
ENCRYPTER_ID=$(sudo docker run -d \
    -v "./mnt/mta":/mnt/mta \
    -v "$LOG_DIR":/var/log \
    danielin322/encrypter:1.0)
echo "Encrypter ${ENCRYPTER_ID} starting..."

# Run decrypters
for ((i=1; i<=NUM_DECRYPTERS; i++)); do
    DEC_ID=$(sudo docker run -d \
        -v "./mnt/mta":/mnt/mta \
        -v "$LOG_DIR":/var/log \
        danielin322/decrypter:1.0)
    echo "Decrypter ${DEC_ID} starting..."
done

echo "System Initialization finished successfully with ${NUM_DECRYPTERS} decrypters"
