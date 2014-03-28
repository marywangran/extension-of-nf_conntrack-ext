
#LINUXPATH = /lib/modules/`uname -r`/build
LINUXPATH = /usr/src/linux-headers-2.6.32-5-amd64-conntrack
CURDIR = $(shell pwd)
KBUILD_OUTPUT = $(CURDIR)
CROSS_COMPILE =
ARCH =

obj-m                           += nf_conn_autort.o 


all: tun

tun:
	$(MAKE) -C $(LINUXPATH) M=$(CURDIR) modules
	@echo "*********************************************"
	@echo "*  The MODULE is OK!!"
	@echo "*********************************************"
.PHONY: clean
clean:
	rm -rf *.o *.ko *.mod.c *.symvers *.mod.o .*.cmd  ../common/*.o .tmp_versions modules.order

 
