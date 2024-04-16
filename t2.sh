#!/bin/bash
sudo rmmod dump_dev1
sudo rmmod work1
sudo rmmod limit1
sudo rm -rf /dev/dump_dev
make clean

make
sudo insmod limit1.ko
sudo insmod work1.ko
sudo insmod dump_dev1.ko
sudo mknod /dev/dump_dev c 232 0
sudo chmod 777 /dev/dump_dev
echo "success\n"


