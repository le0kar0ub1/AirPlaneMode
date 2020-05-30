MODULE=firewall

PWD=$(shell pwd)
IDENTITY=$(shell uname -r)
KERNEL_BUILD=/lib/modules/$(IDENTITY)/build

.PHONY: all clean

obj-m 		+= 	firewall.o

firewall-srcs 	+= $(addprefix kmod/,		\
						   firewall.c	\
						   sysctl.c		\
				)

firewall-objs := ${firewall-srcs:.c=.o}

all:
	make -C $(KERNEL_BUILD) M=$(PWD) modules

install:
	make -C $(KERNEL_BUILD) M=$(PWD) INSTALL_MOD_PATH=$(INSTALL_ROOT) modules_install

clean:
	make -C $(KERNEL_BUILD) M=$(PWD) clean

run:
	sudo dmesg
	sudo modprobe $(MODULE)

stop:
	sudo modprobe -rf $(MODULE)
	sudo dmesg
