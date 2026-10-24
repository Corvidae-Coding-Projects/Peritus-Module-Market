#!/bin/sh
set -eu

count=0
while [ "$count" -lt 20 ]; do
    (while :; do :; done) < "$1" &
    count=$((count + 1))
done
wait
