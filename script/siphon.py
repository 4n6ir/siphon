#!/usr/bin/python3
import os
from subprocess import run

#
# EBS DATA STORAGE
#

os.system('mkdir /data')

ebs = run( [ 'blkid' ], capture_output=True )
drives = ebs.stdout.decode().split('\n')
for drive in drives:
    mount = drive.split(':')
    if mount[0] == '/dev/nvme1n1':
        parse = mount[1].split('"')
        os.system('echo "UUID='+parse[1]+' /data '+parse[3]+' defaults,nofail 0 2" >> /etc/fstab')

os.system('mount -a')
