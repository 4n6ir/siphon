# siphon

### HISTORY

On June 25th, 2019, Amazon Web Services (AWS) released VPC Traffic Mirroring for Nitro-based instances encapsulated over VXLAN on UDP port 4789. Support was expanded on February 10th, 2021, to include limited Xen instance types.

![siphon-data-flow](DATAFLOW.png)

https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-considerations.html

### EXISTING

Three great open-source network security monitoring solutions in alphabetical order already exist!

- Arkime - https://github.com/arkime
- Rock NSM - https://github.com/rocknsm
- Security Onion 2 - https://github.com/Security-Onion-Solutions

### CONFIGURATION

Siphon was built using the Cloud Deployment Kit (CDK) to attach an instance with minimum specifications to an existing VPC that performs network security monitoring using Suricata and Zeek with S3 storage.

Minimum requirements are network connectivity to the monitored resource with an instance that has 2 vCPUs, 2 GiB Memory, and 8 GB Storage here --> https://github.com/jblukach/siphon/blob/main/siphon/siphon_stack.py#L33.

```
vpc_id = 'vpc-04eae279ceb94d7f6'    # <-- Enter VPC ID
ec2_count = 1                       # <-- Enter EC2 Quantity
ec2_type = 't3a.small'              # <-- Enter EC2 Size
ebs_root = 8                        # <-- Enter Root Storage GBs
ebs_data = 4                        # <-- Enter Data Storage GBs
```

A network monitoring interface is attached to every subnet in the configured VPC based on the availability zone.

Ubuntu 20.04 was used for long-term support and software dependencies but does not have AWS CLI installed by default requiring a second installation stage using the SSM agent.

### ZAT

Zeek Analysis Tools (ZAT) from Brian Wylie at Super Cow Powers provides a Python package that converts the compressed Zeek logs to Apache Parquet columnar storage for Athena searches.

https://github.com/SuperCowPowers/zat

### ATHENA

The S3 bucket containing the Parquet files is partitioned by Zeek log, year, month, day, and hostname to limit search volume since it is billed by the terabyte (TB).
