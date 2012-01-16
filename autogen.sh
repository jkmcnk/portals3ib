#! /bin/bash

# Use this script to bootstrap by creating all the needed configure scripts.
# Use "./regen -f" to force every script to be recreated, even if it doesn't
# look it is necessary for any given script.

libtoolize --force
aclocal -I ./m4 && \
autoheader && \
automake --add-missing && \
autoconf

