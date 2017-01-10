#!/bin/bash
make clean
./configure --kerneldir=/home/zhangyy/linux-2.6.38.8
make -j 20
make install
rmmod kvm_intel
rmmod kvm
insmod /home/zhangyy/zyy_rr_test/kvm-kmod-2.6.38.6/x86/kvm.ko
insmod /home/zhangyy/zyy_rr_test/kvm-kmod-2.6.38.6/x86/kvm-intel.ko
