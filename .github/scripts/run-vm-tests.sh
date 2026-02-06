#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# run-vm-tests.sh - Run module tests inside a virtme-ng VM
#
# Boots the specified mainline kernel using virtme-ng (QEMU), loads the
# module, and runs the test suite inside the VM. The host filesystem is
# shared into the VM, so the pre-built module and test scripts are
# accessible.
#
# Usage: ./run-vm-tests.sh <version> <module-dir>
#   version    - kernel version, e.g. "6.8" or "6.12"
#   module-dir - path to the module source directory (with built .ko)
#
# Requires: virtme-ng, qemu-system-x86_64, /dev/kvm (optional but fast)

set -euo pipefail

VERSION="${1:?Usage: $0 <version> <module-dir>}"
MODULE_DIR="${2:?Usage: $0 <version> <module-dir>}"

MODULE_DIR=$(realpath "$MODULE_DIR")
KO_FILE="${MODULE_DIR}/kcore_filtered.ko"

if [ ! -f "$KO_FILE" ]; then
    echo "ERROR: Module not found at ${KO_FILE}" >&2
    echo "Build the module first with: make KDIR=<headers>" >&2
    exit 1
fi

echo "=== VM Test: kernel v${VERSION} ==="
echo "  Module: ${KO_FILE}"
echo "  Working dir: ${MODULE_DIR}"

# Detect KVM availability
VNG_OPTS="--memory 1G --cpus 2"
if [ ! -e /dev/kvm ]; then
    echo "  WARNING: /dev/kvm not available, using TCG (slow)" >&2
    VNG_OPTS="${VNG_OPTS} --disable-kvm"
fi

# Boot the kernel and run all tests inside the VM.
# test_basic.sh handles its own insmod/rmmod cycle.
# After that we reload the module for test_filter.py.
exec vng --run "v${VERSION}" ${VNG_OPTS} -e "
set -e
cd ${MODULE_DIR}

echo '--- test_basic.sh ---'
bash tests/test_basic.sh

echo '--- Reloading module for filter tests ---'
insmod kcore_filtered.ko

echo '--- test_filter.py ---'
python3 tests/test_filter.py

echo '--- Cleaning up ---'
rmmod kcore_filtered

echo '=== All VM tests passed ==='
"
