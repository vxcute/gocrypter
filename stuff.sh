#!/bin/bash

nasm -f elf64 -o $1 $2
readelf -S $1 | grep -A1 ".text"
dd if=$1 count=$(($3)) skip=$((0x180)) bs=1 | xxd -i
