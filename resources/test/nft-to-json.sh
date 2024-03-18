#!/bin/sh
set -e

cd "$(dirname "$0")"

INPUT_DIR=./nft
OUTPUT_DIR=./json

convert_file () {
  INFILE=$1
  unshare -rn sh -exc "nft -f \"${INFILE}\" && nft -j list ruleset"
}

for nftfile in "$INPUT_DIR"/*.nft; do
  convert_file "$nftfile" | jq > "$OUTPUT_DIR/$(basename "$nftfile" .nft).json"
done
