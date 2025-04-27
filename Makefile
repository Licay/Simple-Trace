# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_SIMPLE_TRACE)		+= simple_trace.o
obj-$(CONFIG_SIMPLE_LOOKUP_NAME)	+= simple_lookup_name.o

KVERS = $(shell uname -r)

build: kernel_modules
# CONFIG_SIMPLE_TRACE=m CONFIG_SIMPLE_LOOKUP_NAME=m EXTRA_CFLAGS="-DCONFIG_SIMPLE_TRACE_LOGSIZE_SHIFT=12"

kernel_modules:
	make -C /lib/modules/$(KVERS)/build M=$(CURDIR) modules
clean:
	make -C /lib/modules/$(KVERS)/build M=$(CURDIR) clean
