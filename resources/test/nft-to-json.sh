#!/bin/sh
set -e

cd "$(dirname "$0")"

INPUT_DIR=./nft
OUTPUT_DIR=./json

convert_file () {
  INFILE=$1
  NETNS=nftables
  ip netns delete $NETNS 2>/dev/null || true
  ip netns add $NETNS
  (
    ip netns exec $NETNS nft -f "${INFILE}"
    ip netns exec $NETNS nft -j list ruleset
  ) || true
  ip netns delete $NETNS
}

for nftfile in $INPUT_DIR/*.nft; do
  convert_file $nftfile | jq > $OUTPUT_DIR/$(basename $nftfile .nft).json
done
