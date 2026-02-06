#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# fetch-kernel-headers.sh - Download mainline kernel headers from Ubuntu PPA
#
# Downloads and extracts the linux-headers .deb packages for a given
# mainline kernel version from kernel.ubuntu.com. Used by CI to build
# the module against multiple kernel versions.
#
# Usage: ./fetch-kernel-headers.sh <version> <outdir>
#   version  - kernel version, e.g. "6.8" or "6.12"
#   outdir   - directory to extract headers into
#
# Prints the KDIR path on success, exits non-zero on failure.

set -euo pipefail

VERSION="${1:?Usage: $0 <version> <outdir>}"
OUTDIR="${2:?Usage: $0 <version> <outdir>}"
BASE_URL="https://kernel.ubuntu.com/mainline/v${VERSION}/amd64"

mkdir -p "${OUTDIR}/debs"

echo "Fetching package list from ${BASE_URL}/ ..." >&2

# Get the directory listing and extract header .deb filenames
INDEX=$(curl -sL "${BASE_URL}/")
if [ -z "$INDEX" ]; then
    echo "ERROR: Failed to fetch index from ${BASE_URL}/" >&2
    exit 1
fi

# Extract header .deb filenames (portable grep -oE, no -P)
HEADER_DEBS=$(echo "$INDEX" | grep -oE 'linux-headers[^"<>]*\.deb' | sort -u)

if [ -z "$HEADER_DEBS" ]; then
    echo "ERROR: No linux-headers .deb files found at ${BASE_URL}/" >&2
    exit 1
fi

echo "  Found $(echo "$HEADER_DEBS" | wc -l) header packages" >&2

# Download each header .deb
for deb in $HEADER_DEBS; do
    echo "  Downloading ${deb} ..." >&2
    curl -sL "${BASE_URL}/${deb}" -o "${OUTDIR}/debs/${deb}"
done

# Extract all .debs into the output directory
for deb in "${OUTDIR}/debs/"*.deb; do
    dpkg -x "$deb" "${OUTDIR}"
done

# Find the arch-specific headers directory (the one with Makefile)
KDIR=$(find "${OUTDIR}/usr/src" -maxdepth 1 -name "linux-headers-*-generic" -type d | head -1)

if [ -z "$KDIR" ] || [ ! -f "${KDIR}/Makefile" ]; then
    echo "ERROR: Could not find extracted kernel headers directory" >&2
    echo "  Contents of ${OUTDIR}/usr/src/:" >&2
    ls -la "${OUTDIR}/usr/src/" >&2 || true
    exit 1
fi

echo "  Headers extracted to ${KDIR}" >&2
echo "$KDIR"
