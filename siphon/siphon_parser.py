from aws_cdk import (
    Stack,
    aws_glue as _glue,
    aws_iam as _iam
)

from constructs import Construct

class SiphonParser(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

################################################################################

        vpc_id = 'vpc-04eae279ceb94d7f6'    # <-- Enter VPC ID

################################################################################

        account = Stack.of(self).account
        region = Stack.of(self).region
        archive_name = 'siphon-parquet-'+account+'-'+region+'-'+vpc_id

### IAM ROLE ###

        glue = _iam.Role(
            self, 'glue',
            role_name = 'secops-centralized-cloudfront-logs',
            assumed_by = _iam.ServicePrincipal('glue.amazonaws.com')
        ) 

        glue.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSGlueServiceRole'
            )
        )

        glue.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetObject',
                    's3:PutObject'
                ],
                resources = [
                    'arn:aws:s3:::'+archive_name,
                    'arn:aws:s3:::'+archive_name+'/*'
                ]
            )
        )

### DATABASE ###

        database = _glue.CfnDatabase(
            self, 'database',
            catalog_id = account,
            database_input = _glue.CfnDatabase.DatabaseInputProperty(
                name = 'siphon_'+vpc_id.replace('-','_')
            )
        )

### CONN LOG ###

        conn = _glue.CfnTable(
            self, 'conn',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'conn_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=conn/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #1
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #2
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #3
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #4
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #5
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #6
                            name = 'proto',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #7
                            name = 'service',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #8
                            name = 'duration',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #9
                            name = 'orig_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #10
                            name = 'resp_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #11
                            name = 'conn_state',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #12
                            name = 'local_orig',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #13
                            name = 'local_resp',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #14
                            name = 'missed_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #15
                            name = 'history',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #16
                            name = 'orig_pkts',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #17
                            name = 'orig_ip_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #18
                            name = 'resp_pkts',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #19
                            name = 'resp_ip_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #20
                            name = 'tunnel_parents',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #21
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### DHCP LOG ###

        dhcp = _glue.CfnTable(
            self, 'dhcp',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'dhcp_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=dhcp/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uids',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'client_addr',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'server_addr',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'mac',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'host_name',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'client_fqdn',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'domain',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'requested_addr',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'assigned_addr',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'lease_time',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'client_message',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'server_message',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'msg_types',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'duration',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### DNS LOG ###

        dns = _glue.CfnTable(
            self, 'dns',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'dns_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=dns/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'proto',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'trans_id',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'rtt',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'query',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'qclass',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'qclass_name',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'qtype',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'qtype_name',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'rcode',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'rcode_name',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'aa',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'tc',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'rd',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ra',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'z',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'answers',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ttls',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'rejected',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### DPD LOG ###

        dpd = _glue.CfnTable(
            self, 'dpd',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'dpd_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=dpd/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'proto',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'analyzer',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'failure_reason',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### FILES LOG ###

        files = _glue.CfnTable(
            self, 'files',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'files_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=files/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'fuid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'tx_hosts',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'rx_hosts',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'conn_uids',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'source',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'depth',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'analyzers',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'mime_type',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'filename',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'duration',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'local_orig',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'is_orig',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'seen_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'total_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'missing_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'overflow_bytes',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'timedout',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'parent_fuid',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'md5',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'sha1',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'sha256',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'extracted',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'extracted_cutoff',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'extracted_size',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### HTTP LOG ###

        http = _glue.CfnTable(
            self, 'http',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'http_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=http/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'trans_depth',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'method',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'host',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uri',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'referrer',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'version',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'user_agent',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'origin',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'request_body_len',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'response_body_len',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'status_code',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'status_msg',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'info_code',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'info_msg',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'tags',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'username',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'password',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'proxied',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'orig_fuids',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'orig_filenames',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'orig_mime_types',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'resp_fuids',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'resp_filenames',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'resp_mime_types',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### NTP LOG ###

        ntp = _glue.CfnTable(
            self, 'ntp',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'ntp_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=ntp/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'version',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'mode',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'stratum',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'poll',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'precision',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'root_delay',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'root_disp',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ref_id',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ref_time',
                            type = 'timestamp'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'org_time',
                            type = 'timestamp'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'rec_time',
                            type = 'timestamp'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'xmt_time',
                            type = 'timestamp'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'num_exts',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )
        
### SSL LOG ###

        ssl = _glue.CfnTable(
            self, 'ssl',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'ssl_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=ssl/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'version',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'cipher',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'curve',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'server_name',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'resumed',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'last_alert',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'next_protocol',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'established',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'cert_chain_fuids',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'client_cert_chain_fuids',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'subject',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'issuer',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'client_subject',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'client_issuer',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'validation_status',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### TUNNEL LOG ###

        tunnel = _glue.CfnTable(
            self, 'tunnel',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'tunnel_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=tunnel/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'tunnel_type',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'action',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### WEIRD LOG ###

        weird = _glue.CfnTable(
            self, 'weird',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'weird_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=weird/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'uid',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.orig_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_h',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id.resp_p',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'name',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'addl',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'notice',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'peer',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'source',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )

### X509 LOG ###

        x509 = _glue.CfnTable(
            self, 'x509',
            catalog_id = account,
            database_name = 'siphon_'+vpc_id.replace('-','_'),
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'x509_'+vpc_id.replace('-','_'),
                parameters = {
                    'classification': 'parquet'
                },
                partition_keys = [],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=x509/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                    ),
                    columns = [
                        _glue.CfnTable.ColumnProperty( #
                            name = 'id',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.version',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.serial',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.subject',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.issuer',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.not_valid_before',
                            type = 'timestamp'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.not_valid_after',
                            type = 'timestamp'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.key_alg',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.sig_alg',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.key_type',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.key_length',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.exponent',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'certificate.curve',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'san.dns',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'san.uri',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'san.email',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'san.ip',
                            type = 'int'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'basic_constraints.ca',
                            type = 'string'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'basic_constraints.path_len',
                            type = 'bigint'
                        ),
                        _glue.CfnTable.ColumnProperty( #
                            name = 'ts',
                            type = 'timestamp'
                        )
                    ]
                )
            )
        )