# siphon
Three great open-source network security monitoring solutions exist!
- Arkime - https://github.com/arkime
- Rock NSM - https://github.com/rocknsm
- Security Onion 2 - https://github.com/Security-Onion-Solutions

Why would we need yet another version? 
- Infrastructure as Code
- Minimum Specifications
### CONFIGURATION
Minimum requirements are network connectivity to the monitored resource with an instance that has 2 vCPUs, 2 GiB Memory, and 8 GB Storage here --> https://github.com/4n6ir/siphon/blob/main/siphon/siphon_stack.py#L16.
```
vpc_id = 'vpc-<number>'
ec2_count = 1
ec2_type = 't3a.small'
ebs_gb = 8
```
A network monitoring interface is attached to every subnet in the configured VPC.
### NETWORK MONITORING
VPC Traffic Mirroring is available on Nitro-based EC2 instances and select non-Nitro based EC2 types: C4, D2, G3, G3s, H1, I3, M4, P2, P3, R4, X1, and X1e.
https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html
