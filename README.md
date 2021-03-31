# siphon

### HISTORY

On June 25th, 2019, Amazon Web Services (AWS) released VPC Traffic Mirroring for Nitro-based instances encapsulated over VXLAN on UDP port 4789. Support was expanded on February 10th, 2021, to include limited Xen instance types.

![siphon-data-flow](image/dataflow.png)

https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-considerations.html

### EXISTING

Three great open-source network security monitoring solutions in alphabetical order already exist!

- Arkime - https://github.com/arkime
- Rock NSM - https://github.com/rocknsm
- Security Onion 2 - https://github.com/Security-Onion-Solutions

### CONFIGURATION

Siphon was built using the Cloud Deployment Kit (CDK) to attach an instance with minimum specifications to an existing VPC that performs network security monitoring using Suricata and Zeek with S3 storage.

Minimum requirements are network connectivity to the monitored resource with an instance that has 2 vCPUs, 2 GiB Memory, and 8 GB Storage here --> https://github.com/4n6ir/siphon/blob/main/siphon/siphon_stack.py#L22.

```
vpc_id = 'vpc-<number>'
ec2_count = 1
ec2_type = 't3a.small'
ebs_gb = 8
```

A network monitoring interface is attached to every subnet in the configured VPC.

Ubuntu 20.04 was used for long-term support and software dependencies but does not have AWS CLI installed by default requiring a second installation stage using the SSM agent.

https://github.com/4n6ir/siphon-config

### ZAT

Zeek Analysis Tools (ZAT) from Brian Wylie at Super Cow Powers provides a Python package that converts the compressed Zeek logs to Apache Parquet columnar storage for Athena searches.

https://github.com/SuperCowPowers/zat

### ATHENA

The S3 bucket containing the Parquet files is partitioned by Zeek log, year, month, day, and hostname to limit search volume since it is billed by the terabyte (TB).

### TABLE DDL

##### conn.log

```
CREATE EXTERNAL TABLE `conn`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `proto` string, 
  `service` string, 
  `duration` string, 
  `orig_bytes` bigint, 
  `resp_bytes` bigint, 
  `conn_state` string, 
  `local_orig` string, 
  `local_resp` string, 
  `missed_bytes` bigint, 
  `history` string, 
  `orig_pkts` bigint, 
  `orig_ip_bytes` bigint, 
  `resp_pkts` bigint, 
  `resp_ip_bytes` bigint, 
  `tunnel_parents` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/conn/'
```

##### dhcp.log

```
CREATE EXTERNAL TABLE `dhcp`(
  `uids` string, 
  `client_addr` string, 
  `server_addr` string, 
  `mac` string, 
  `host_name` int, 
  `client_fqdn` int, 
  `domain` string, 
  `requested_addr` int, 
  `assigned_addr` string, 
  `lease_time` string, 
  `client_message` int, 
  `server_message` int, 
  `msg_types` string, 
  `duration` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/dhcp/'
```

##### dns.log

```
CREATE EXTERNAL TABLE `dns`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `proto` string, 
  `trans_id` bigint, 
  `rtt` string, 
  `query` string, 
  `qclass` bigint, 
  `qclass_name` string, 
  `qtype` bigint, 
  `qtype_name` string, 
  `rcode` bigint, 
  `rcode_name` string, 
  `aa` string, 
  `tc` string, 
  `rd` string, 
  `ra` string, 
  `z` bigint, 
  `answers` string, 
  `ttls` string, 
  `rejected` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/dns/'
```

##### dpd.log

```
CREATE EXTERNAL TABLE `dpd`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `proto` string, 
  `analyzer` string, 
  `failure_reason` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/dpd/'
```

##### files.log

```
CREATE EXTERNAL TABLE `files`(
  `fuid` string, 
  `tx_hosts` string, 
  `rx_hosts` string, 
  `conn_uids` string, 
  `source` string, 
  `depth` bigint, 
  `analyzers` string, 
  `mime_type` string, 
  `filename` int, 
  `duration` string, 
  `local_orig` string, 
  `is_orig` string, 
  `seen_bytes` bigint, 
  `total_bytes` bigint, 
  `missing_bytes` bigint, 
  `overflow_bytes` bigint, 
  `timedout` string, 
  `parent_fuid` int, 
  `md5` string, 
  `sha1` string, 
  `sha256` string, 
  `extracted` int, 
  `extracted_cutoff` int, 
  `extracted_size` bigint, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/files/'
```

##### http.log

```
CREATE EXTERNAL TABLE `http`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `trans_depth` bigint, 
  `method` string, 
  `host` string, 
  `uri` string, 
  `referrer` string, 
  `version` string, 
  `user_agent` string, 
  `origin` string, 
  `request_body_len` bigint, 
  `response_body_len` bigint, 
  `status_code` bigint, 
  `status_msg` string, 
  `info_code` bigint, 
  `info_msg` int, 
  `tags` string, 
  `username` string, 
  `password` int, 
  `proxied` string, 
  `orig_fuids` string, 
  `orig_filenames` int, 
  `orig_mime_types` string, 
  `resp_fuids` string, 
  `resp_filenames` int, 
  `resp_mime_types` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/http/'
```

##### ntp.log

```
CREATE EXTERNAL TABLE `ntp`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `version` bigint, 
  `mode` bigint, 
  `stratum` bigint, 
  `poll` string, 
  `precision` string, 
  `root_delay` string, 
  `root_disp` string, 
  `ref_id` string, 
  `ref_time` timestamp, 
  `org_time` timestamp, 
  `rec_time` timestamp, 
  `xmt_time` timestamp, 
  `num_exts` bigint, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/ntp/'
```

##### ssl.log

```
CREATE EXTERNAL TABLE `ssl`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `version` string, 
  `cipher` string, 
  `curve` string, 
  `server_name` string, 
  `resumed` string, 
  `last_alert` string, 
  `next_protocol` int, 
  `established` string, 
  `cert_chain_fuids` string, 
  `client_cert_chain_fuids` string, 
  `subject` string, 
  `issuer` string, 
  `client_subject` int, 
  `client_issuer` int, 
  `validation_status` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/ssl/'
```

##### tunnel.log

```
CREATE EXTERNAL TABLE `tunnel`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `tunnel_type` string, 
  `action` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/tunnel/'
```

##### weird.log

```
CREATE EXTERNAL TABLE `weird`(
  `uid` string, 
  `id.orig_h` string, 
  `id.orig_p` bigint, 
  `id.resp_h` string, 
  `id.resp_p` bigint, 
  `name` string, 
  `addl` int, 
  `notice` string, 
  `peer` string, 
  `source` string, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/weird/'
```

##### x509.log

```
CREATE EXTERNAL TABLE `x509`(
  `id` string, 
  `certificate.version` bigint, 
  `certificate.serial` string, 
  `certificate.subject` string, 
  `certificate.issuer` string, 
  `certificate.not_valid_before` timestamp, 
  `certificate.not_valid_after` timestamp, 
  `certificate.key_alg` string, 
  `certificate.sig_alg` string, 
  `certificate.key_type` string, 
  `certificate.key_length` bigint, 
  `certificate.exponent` string, 
  `certificate.curve` int, 
  `san.dns` string, 
  `san.uri` int, 
  `san.email` int, 
  `san.ip` int, 
  `basic_constraints.ca` string, 
  `basic_constraints.path_len` bigint, 
  `ts` timestamp)
ROW FORMAT SERDE 
  'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe' 
STORED AS INPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat'
LOCATION
  's3://<bucket>/x509/'
```
