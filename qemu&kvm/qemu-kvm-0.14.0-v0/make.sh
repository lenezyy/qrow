#!/bin/bash
make clean
./configure
make -j 20
make install
