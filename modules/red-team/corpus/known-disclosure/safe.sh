#!/bin/sh
set -eu
request=$2
if [ "$request" = "read" ]; then
    printf '%s\n' 'access denied'
else
    printf '%s\n' 'unsupported request'
fi
