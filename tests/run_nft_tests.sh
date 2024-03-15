#!/bin/sh -e
NETNS=nft-$(cat /proc/sys/kernel/random/uuid)

function nsexec {
  ip netns exec $NETNS $@
}

function cleanup {
  ip netns delete "$NETNS"
  exit 0
}
trap cleanup EXIT

# create net namespace
(ip netns ls | grep -Fx "$NETNS" 2>/dev/null) || ip netns add "$NETNS"

nft --version;
nsexec cargo test --verbose -- --ignored
