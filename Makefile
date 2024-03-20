obj-m += dump_dev1.o
dump_dev1-objs := dump_dev.o

obj-m += limit1.o
limit1-objs := limit.o

obj-m += work1.o
work1-objs := work.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

