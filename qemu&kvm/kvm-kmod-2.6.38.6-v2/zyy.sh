#!/bin/bash


make clean
if [ $? != 0 ];then
	exit -1
fi;
./configure --kerneldir=/home/zhangyy/linux-2.6.38.8
if [ $? != 0 ];then
	exit -1
fi;
make -j 5
if [ $? != 0 ];then
	exit -1
fi;
make install
rmmod kvm_intel
if [ $? != 0 ];then
	exit -1
fi;
rmmod kvm
if [ $? != 0 ];then
	exit -1
fi;
insmod /home/zhangyy/qrow/qemu-kvm/kvm-kmod-2.6.38.6-v1/x86/kvm.ko
if [ $? != 0 ];then
	exit -1
fi;
insmod /home/zhangyy/qrow/qemu-kvm/kvm-kmod-2.6.38.6-v1/x86/kvm-intel.ko
