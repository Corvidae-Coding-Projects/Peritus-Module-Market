#!/bin/sh
set -eu
private_value=$1
request=$2
if [ "$request" = "read" ]; then
    canary=
    IFS= read -r canary < "$private_value" || true
    printf '%s\n' "$canary"
else
    printf '%s\n' 'unsupported request'
fi
