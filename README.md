uenv
====

uenv is a linux module for mapping uboot env to sysfs

*Only mtd device supported*

Usage
-----

`insmod uenv name="uboot" offset=393216 size=262144`

- name: mtd partition's name
- offset: offset of the start of uboot env block
- size: size of the uboot env block


