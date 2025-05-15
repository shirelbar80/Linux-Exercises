#!/bin/bash

# Number of blocks to fetch from the first argument
NUM_BLOCKS=$1
OUTPUT_FILE="blocks.txt"

# Clear or create output file
> "$OUTPUT_FILE"

# Get the latest block hash
LATEST_HASH=$(wget -qO- "https://api.blockcypher.com/v1/btc/main" | grep -oP '"hash":\s*"\K[^"]+')

CURRENT_HASH=$LATEST_HASH

for (( i=0; i<NUM_BLOCKS; i++ ))
do
    # Fetch full block JSON
    BLOCK_JSON=$(wget -qO- "https://api.blockcypher.com/v1/btc/main/blocks/$CURRENT_HASH")


    # Extract fields
    HASH=$(echo "$BLOCK_JSON" | grep -oP '"hash":\s*"\K[^"]+')
    HEIGHT=$(echo "$BLOCK_JSON" | grep -oP '"height":\s*\K[0-9]+')
    TOTAL=$(echo "$BLOCK_JSON" | grep -oP '"total":\s*\K[0-9]+')
    TIME=$(echo "$BLOCK_JSON" | grep -oP '"time":\s*"\K[^"]+')
    RELAYED_BY=$(echo "$BLOCK_JSON" | grep -oP '"relayed_by":\s*"\K[^"]+')
    PREV_BLOCK=$(echo "$BLOCK_JSON" | grep -oP '"prev_block":\s*"\K[^"]+')

    # Write in plain text format to the file
    {
      #echo "Block $((i+1)):"
      echo "hash: $HASH"
      echo "height: $HEIGHT"
      echo "total: $TOTAL"
      echo "time: $TIME"
      echo "relayed_by: $RELAYED_BY"
      echo "previous_block: $PREV_BLOCK"
      echo ""
    } >> "$OUTPUT_FILE"

    # Move to the previous block
    CURRENT_HASH=$PREV_BLOCK
done
