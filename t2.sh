#!/bin/bash
sudo rmmod work1
make clean

make
sudo insmod work1.ko
echo "success\n"


