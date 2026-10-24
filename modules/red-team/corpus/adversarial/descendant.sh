#!/bin/sh
set -eu

(while :; do :; done) < "$1" &
wait
