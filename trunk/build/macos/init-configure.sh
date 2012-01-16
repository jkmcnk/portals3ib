#!/bin/bash

# Configures portals with the user-space TCP nal. 

#../../configure --enable-utcp-nal --disable-threaded-library $@
../../configure --enable-utcp-nal --enable-threaded-library $@
