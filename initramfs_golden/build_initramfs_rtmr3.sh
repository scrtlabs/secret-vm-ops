
cd initramfs_rtmr3

find . | sudo cpio -o --format=newc | gzip > ../initramfs_rtmr3.img

cd ..
