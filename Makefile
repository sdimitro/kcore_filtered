# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for kcore_filtered - privacy-filtered /proc/kcore alternative
#
# Usage:
#   make                       - build the module
#   make KDIR=/path/to/kernel  - build against a specific kernel tree
#   make checkpatch            - run checkpatch.pl on all source files
#   make sparse                - build with sparse static analysis
#   make test                  - run the test suite (requires root + loaded module)
#   make clean                 - clean build artifacts
#

MODULE_NAME := kcore_filtered
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := kcore_filtered_main.o page_filter.o elf_core.o region.o

# Kernel build directory - override with KDIR=/path/to/6.8+-tree
KDIR ?= /lib/modules/$(shell uname -r)/build

# Source files for linting (exclude auto-generated .mod.c)
SRCS := $(filter-out %.mod.c,$(wildcard *.c *.h))

# Checkpatch script location
CHECKPATCH := $(KDIR)/scripts/checkpatch.pl

# Default target
all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

# Run checkpatch.pl on all source files
checkpatch:
	@if [ ! -f "$(CHECKPATCH)" ]; then \
		echo "ERROR: checkpatch.pl not found at $(CHECKPATCH)"; \
		echo "Set KDIR to a kernel source tree that contains scripts/checkpatch.pl"; \
		exit 1; \
	fi
	@echo "=== Running checkpatch.pl ==="
	@for f in $(SRCS); do \
		echo "--- Checking $$f ---"; \
		$(CHECKPATCH) --no-tree --no-signoff -f $$f || true; \
	done

# Run sparse static analysis
sparse:
	$(MAKE) -C $(KDIR) M=$(CURDIR) C=1 modules

# Run coccinelle semantic patches (if available)
coccicheck:
	$(MAKE) -C $(KDIR) M=$(CURDIR) coccicheck MODE=report

# Run the test suite
test:
	@echo "=== Running basic tests (includes filter_slab=1) ==="
	@sudo bash tests/test_basic.sh
	@echo ""
	@echo "=== Running filter validation ==="
	@sudo python3 tests/test_filter.py
	@echo ""
	@echo "=== Running drgn integration tests ==="
	@sudo python3 tests/test_drgn.py

# Run filter_slab=1 validation (module must be loaded with filter_slab=1)
test-slab:
	@echo "=== Running filter validation with filter_slab=1 ==="
	@sudo python3 tests/test_filter.py --filter-slab

# Install the module
install:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules_install

# Convenience: load and unload
load:
	sudo insmod $(MODULE_NAME).ko

unload:
	sudo rmmod $(MODULE_NAME)

reload: unload load

.PHONY: all modules clean checkpatch sparse coccicheck test test-slab install load unload reload
