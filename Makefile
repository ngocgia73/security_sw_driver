ARCH:=arm 
COMPILER:=/usr/local/arm-linux-gm/bin/arm-linux-
KERNELDIR:=/home/giann/hubble_working/BT_project/final/kernel_source/gm/kernel/normal_build
PWD := $(shell pwd)
obj-m += aes_des_sw.o
all:
	make -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) modules
	arm-linux-gcc -o app_test app_test.c
clean:
	make -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) clean
	rm -f app_test
