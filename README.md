# kcore_filtered

[![CI](https://github.com/sdimitropoulos/kcore_filtered/actions/workflows/ci.yml/badge.svg)](https://github.com/sdimitropoulos/kcore_filtered/actions/workflows/ci.yml)

A Linux kernel module that creates `/proc/kcore_filtered` — a
privacy-filtered alternative to `/proc/kcore`. Kernel memory is
exposed in ELF core format (readable by **drgn**, readelf, crash) but
user-space pages are redacted to zeroes.

## Quick Start

```bash
make
sudo insmod kcore_filtered.ko
sudo drgn -c /proc/kcore_filtered   # safe kernel introspection
```

## Build & Test

```bash
make                # build the module
make checkpatch     # kernel style check (0 errors, 0 warnings)
make sparse         # static analysis
make test           # full test suite (requires root + loaded module)
```

## Filter Policy

| Page Type | Default |
|---|---|
| Anonymous / swap-backed | **DENY** (zeroes) |
| Free / buddy | **DENY** |
| User page cache | **DENY** |
| Slab (kernel objects) | allow (configurable) |
| Kernel text / vmalloc / vmemmap | allow |

Tune at load time: `sudo insmod kcore_filtered.ko filter_slab=1`

## License

GPL-2.0-only — see [LICENSE](LICENSE).
