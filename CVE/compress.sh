#!/bin/sh
gcc -static -pthread ./exploit.c -o ./exploit
mv ./exploit ./rootfs
cp ./exploit.c ./rootfs
cd rootfs
find . | cpio -o -H newc | gzip > rootfs.cpio.gz
mv ./rootfs.cpio.gz ../
cd ..
#./run.sh
