#!/bin/sh

set -e

autoreconf -i
exec ./configure "$@"
