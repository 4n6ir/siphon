#!/usr/bin/python3
import boto3
import json
import os
import socket
import requests
import yaml
from subprocess import run

### EBS DATA STORAGE ###

os.system('mkfs -t ext4 /dev/nvme1n1')
os.system('mkdir /data')

ebs = run( [ 'blkid' ], capture_output=True )
drives = ebs.stdout.decode().split('\n')
for drive in drives:
    mount = drive.split(':')
    if mount[0] == '/dev/nvme1n1':
        parse = mount[1].split('"')
        os.system('echo "UUID='+parse[1]+' /data '+parse[3]+' defaults,nofail 0 2" >> /etc/fstab')

os.system('mount -a')

### LIST MONITORING INTERFACES ###

inet = []
socks = socket.if_nameindex()
for sock in socks:
    if sock[1] != 'ens5' and sock[1] != 'lo':
        inet.append(sock[1])

### CONFIGURED ENI ###

for net in inet:
    os.system('/usr/sbin/ip link set ens'+net[3:]+' up')
    os.system('/usr/sbin/ip link set ens'+net[3:]+' mtu 9100')
    os.system('/usr/sbin/ethtool --offload ens'+net[3:]+' tx off')

### ZEEK CONFIGURATION ###

os.system('cp /opt/zeek/etc/zeekctl.cfg /opt/zeek/etc/zeekctl.cfg.bkp')

f = open('/opt/zeek/etc/zeekctl.cfg', 'r')
data = f.read()
data = data.replace("/opt/zeek/logs","/data")
f.close()

f = open('/opt/zeek/etc/zeekctl.cfg', 'w')
f.write(data)
f.close()   

os.system('cp /opt/zeek/etc/node.cfg /opt/zeek/etc/node.cfg.bkp')

f = open('/opt/zeek/etc/node.cfg','w')

f.write('[logger]\n')
f.write('type=logger\n')
f.write('host=localhost\n\n')
f.write('[manager]\n')
f.write('type=manager\n')
f.write('host=localhost\n\n')
f.write('[proxy-1]\n')
f.write('type=proxy\n')
f.write('host=localhost\n\n')

for net in inet:
    f.write('[worker-'+net[3:]+']\n')
    f.write('type=worker\n')
    f.write('host=localhost\n')
    f.write('interface=af_packet::ens'+net[3:]+'\n\n')

f.close()

os.system('/opt/zeek/bin/zeekctl install')
os.system('/opt/zeek/bin/zeekctl start')

### SURICATA CONFIGURATION ###

os.system('cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bkp')

stream = open('/etc/suricata/suricata.yaml', 'r')
data = yaml.load(stream, Loader=yaml.FullLoader)

cluster = 99
count = 0
for net in inet:
    data['af-packet'][count]['interface'] = net
    data['af-packet'][count]['cluster-id'] = cluster
    data['af-packet'][count]['cluster-type'] = 'cluster_flow'
    data['af-packet'][count]['defrag'] = True
    cluster -= 1
    count += 1

with open('/etc/suricata/suricata.yaml', 'w') as yaml_file:
    yaml_file.write('%YAML 1.1\n')
    yaml_file.write('---\n\n')
    yaml_file.write(yaml.dump(data, default_flow_style=False))

os.system('suricata-update')
os.system('systemctl start suricata')
os.system('systemctl enable suricata')

### S3 BUCKET NAME ###

headers = {'X-aws-ec2-metadata-token-ttl-seconds': '30'}
token = requests.put('http://169.254.169.254/latest/api/token', headers=headers)

headers = {'X-aws-ec2-metadata-token': token.text}

r = requests.get('http://169.254.169.254/latest/meta-data/instance-id', headers=headers)
instance = r.text

r = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document', headers=headers)
j = json.loads(r.text)
region = j['region']

client = boto3.client('ec2', region_name=region)

response = client.describe_instances(
    InstanceIds=[
        instance
    ]
)

vpc = response['Reservations'][0]['Instances'][0]['VpcId']

parameter = boto3.client('ssm', region_name=region)
response = parameter.get_parameter(Name='/siphon/'+vpc+'/bucket')
bucket = response['Parameter']['Value']

os.system('touch /root/'+bucket)

### SETUP CRONTAB ###

os.system('cp /etc/crontab /etc/crontab.bkp')

f = open('/etc/crontab','a')
f.write('#\n')
f.write('*/5 * * * * root /opt/zeek/bin/zeekctl cron\n')
f.write('*/15 * * * * root /usr/local/bin/aws s3 sync /data s3://'+bucket+'/`hostname` --exclude "*" --include "*.log.gz"\n')
f.write('0 11 * * * root /usr/bin/suricata-update\n')
f.write('15 11 * * * root /usr/bin/systemctl restart suricata\n')
f.write('0 * * * * root /usr/bin/find /data/* -mtime +7 -type f -name "*.log.gz" -delete\n')
f.write('#')
f.close()

os.system('systemctl restart cron')

### CONFIGURED STARTUP ###

f = open('/etc/systemd/system/rc-local.service','w')

f.write('[Unit]\n')
f.write('Description=/etc/rc.local Compatibility\n')
f.write('ConditionPathExists=/etc/rc.local\n\n')
f.write('[Service]\n')
f.write('Type=forking\n')
f.write('ExecStart=/etc/rc.local start\n')
f.write('TimeoutSec=0\n')
f.write('StandardOutput=tty\n')
f.write('RemainAfterExit=yes\n')
f.write('SysVStartPriority=99\n\n')
f.write('[Install]\n')
f.write('WantedBy=multi-user.target\n')

f.close()

f = open('/etc/rc.local','w')

f.write('#!/usr/bin/bash\n')

for net in inet:
    f.write('/usr/sbin/ip link set ens'+net[3:]+' up\n')
    f.write('/usr/sbin/ip link set ens'+net[3:]+' mtu 9100\n')
    f.write('/usr/sbin/ethtool --offload ens'+net[3:]+' tx off\n')

f.write('/opt/zeek/bin/zeekctl start\n')
f.write('exit 0\n')

f.close()

os.system('chmod +x /etc/rc.local')
os.system('systemctl enable rc-local')
os.system('systemctl start rc-local')

### REBOOT INSTALL ###

os.system('init 6')