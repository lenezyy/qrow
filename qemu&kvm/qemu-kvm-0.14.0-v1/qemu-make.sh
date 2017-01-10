#!/bin/hash
make clean
./configure --prefix=/home/zhangyy/qrow/qemu-kvm/qemu-install
make -j 5
make install
