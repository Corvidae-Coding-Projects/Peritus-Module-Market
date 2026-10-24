#!/bin/sh
set -eu

block=x
count=0
while [ "$count" -lt 12 ]; do
    block="$block$block"
    count=$((count + 1))
done
while printf '%s' "$block" >> storage-pressure.bin; do :; done
exit 73
