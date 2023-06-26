about
--------
Some sort of virtual disk (kernel module)   
Written with educational purpose, not from ground   

compile
--------
make   
**NOTE: you should have kernel headers installed (tested on 6.4.0)**   

load
--------
*To use as a RAM disk*   
insmod vbde.ko [capacity=*desired_size_in_mib*]  
 
*To use as a proxy to some other block device*   
**(WARNING: this mode is broken, always zeroes are read/written, future investigation is required)**   
insmod vbde.ko [lld=*path_to_device*]   

test
--------
*Copy 4 Mib of random data to tmp*   
dd if=/dev/random of=/tmp/1 bs=4k count=1024  
 
*Copy 4 Mib of data to disk*   
dd if=/tmp/1 of=/dev/vbde bs=4k count=1024   

*Copy 4 Mib of data from disk*   
dd if=/dev/vbde of=/tmp/2 bs=4k count=1024  
 
*Check integrity, should be the same*   
md5sum /tmp/1 /tmp/2   

unload
--------
rmmod vbde.ko   
