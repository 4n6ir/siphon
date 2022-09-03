from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_glue_alpha as _glue,
    aws_iam as _iam,
    aws_s3 as _s3,
)

from constructs import Construct

class SiphonParser(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

################################################################################

        vpc_id = 'vpc-0aa03892e4dcb8332'    # <-- Enter VPC ID

################################################################################

        account = Stack.of(self).account
        region = Stack.of(self).region
        archive_name = 'siphon-parquet-'+account+'-'+region+'-'+vpc_id

        archive = _s3.Bucket(
            self, 'archive',
            bucket_name = archive_name,
            encryption = _s3.BucketEncryption.KMS_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True
        )

### IAM ROLE ###

        glue = _iam.Role(
            self, 'glue',
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

        database = _glue.Database(
            self, 'database',
            database_name = 'siphon_'+vpc_id.replace('-','_')
        )

### BROKER LOG ###

        broker =  _glue.Table(
            self, 'broker',
            bucket = archive,
            database = database,
            s3_prefix = 'service=broker',
            table_name = 'broker_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'ev',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'message',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'peer.address',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'peer.bound_port',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'ty',
                    type = _glue.Schema.STRING
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### CAPTURE LOSS LOG ###

        capture_loss =  _glue.Table(
            self, 'capture_loss',
            bucket = archive,
            database = database,
            s3_prefix = 'service=capture_loss',
            table_name = 'capture_loss_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'acks',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'gaps',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'peer',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'percent_lost',
                    type = _glue.Schema.DOUBLE
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'ts_delta',
                    type = _glue.Schema.STRING
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### CLUSTER LOG ###

        cluster =  _glue.Table(
            self, 'cluster',
            bucket = archive,
            database = database,
            s3_prefix = 'service=cluster',
            table_name = 'cluster_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'message',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'node',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### CONN LOG ###

        conn =  _glue.Table(
            self, 'conn',
            bucket = archive,
            database = database,
            s3_prefix = 'service=conn',
            table_name = 'conn_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'proto',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'service',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'duration',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'orig_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'resp_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'conn_state',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'local_orig',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'local_resp',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'missed_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'history',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'orig_pkts',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'orig_ip_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'resp_pkts',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'resp_ip_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'tunnel_parents',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### DHCP LOG ###

        dhcp =  _glue.Table(
            self, 'dhcp',
            bucket = archive,
            database = database,
            s3_prefix = 'service=dhcp',
            table_name = 'dhcp_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uids',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'client_addr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'server_addr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'mac',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'host_name',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'client_fqdn',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'domain',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'requested_addr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'assigned_addr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'lease_time',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'client_message',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'server_message',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'msg_types',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'duration',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### DNS LOG ###

        dns =  _glue.Table(
            self, 'dns',
            bucket = archive,
            database = database,
            s3_prefix = 'service=dns',
            table_name = 'dns_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                        type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'proto',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'trans_id',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'rtt',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'query',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'qclass',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'qclass_name',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'qtype',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'qtype_name',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'rcode',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'rcode_name',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'aa',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'tc',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'rd',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ra',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'z',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'answers',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ttls',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'rejected',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### DPD LOG ###

        dpd =  _glue.Table(
            self, 'dpd',
            bucket = archive,
            database = database,
            s3_prefix = 'service=dpd',
            table_name = 'dpd_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'proto',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'analyzer',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'failure_reason',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### FILES LOG ###

        files =  _glue.Table(
            self, 'files',
            bucket = archive,
            database = database,
            s3_prefix = 'service=files',
            table_name = 'files_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'fuid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'tx_hosts',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'rx_hosts',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'conn_uids',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'source',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'depth',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'analyzers',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'mime_type',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'filename',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'duration',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'local_orig',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'is_orig',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'seen_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'total_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'missing_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'overflow_bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'timedout',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'parent_fuid',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'md5',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'sha1',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'sha256',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'extracted',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'extracted_cutoff',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'extracted_size',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### HTTP LOG ###

        http =  _glue.Table(
            self, 'http',
            bucket = archive,
            database = database,
            s3_prefix = 'service=http',
            table_name = 'http_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'trans_depth',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'method',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'host',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'uri',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'referrer',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'version',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'user_agent',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'origin',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'request_body_len',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'response_body_len',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'status_code',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'status_msg',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'info_code',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'info_msg',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'tags',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'username',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'password',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'proxied',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'orig_fuids',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'orig_filenames',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'orig_mime_types',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'resp_fuids',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'resp_filenames',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'resp_mime_types',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### KERBEROS LOG ###

        kerberos =  _glue.Table(
            self, 'kerberos',
            bucket = archive,
            database = database,
            s3_prefix = 'service=kerberos',
            table_name = 'kerberos_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'cipher',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'client',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'client_cert_fuid',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'client_cert_subject',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'error_msg',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'forwardable',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'from',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'renewable',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'request_type',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'server_cert_fuid',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'server_cert_subject',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'service',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'success',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'till',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### KNOWN CERTS LOG ###

        known_certs =  _glue.Table(
            self, 'known_certs',
            bucket = archive,
            database = database,
            s3_prefix = 'service=known_certs',
            table_name = 'known_certs_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'host',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'issuer_subject',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'port_num',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'serial',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'subject',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### KNOWN HOSTS LOG ###

        known_hosts =  _glue.Table(
            self, 'known_hosts',
            bucket = archive,
            database = database,
            s3_prefix = 'service=known_hosts',
            table_name = 'known_hosts_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'host',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### KNOWN SERVICES LOG ###

        known_services =  _glue.Table(
            self, 'known_services',
            bucket = archive,
            database = database,
            s3_prefix = 'service=known_services',
            table_name = 'known_services_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'host',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'port_num',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'port_proto',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'service',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### NOTICE LOG ###

        notice =  _glue.Table(
            self, 'notice',
            bucket = archive,
            database = database,
            s3_prefix = 'service=notice',
            table_name = 'notice_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'actions',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'dst',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'file_desc',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'file_mime_type',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'fuid',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'msg',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'n',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'note',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'p',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'peer_descr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'proto',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'remote_location.city',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'remote_location.country_code',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'remote_location.latitude',
                    type = _glue.Schema.DOUBLE
                ),
                _glue.Column(
                    name = 'remote_location.longitude',
                    type = _glue.Schema.DOUBLE
                ),

                _glue.Column(
                    name = 'remote_location.region',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'src',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'sub',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'suppress_for',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.INTEGER
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### NTP LOG ###

        ntp =  _glue.Table(
            self, 'ntp',
            bucket = archive,
            database = database,
            s3_prefix = 'service=ntp',
            table_name = 'ntp_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'version',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'mode',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'stratum',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'poll',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'precision',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'root_delay',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'root_disp',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ref_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ref_time',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'org_time',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'rec_time',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'xmt_time',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'num_exts',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### PACKET FILTER LOG ###

        packet_filter =  _glue.Table(
            self, 'packet_filter',
            bucket = archive,
            database = database,
            s3_prefix = 'service=packet_filter',
            table_name = 'packet_filter_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'filter',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'init',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'node',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'success',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### SOFTWARE LOG ###

        software =  _glue.Table(
            self, 'software',
            bucket = archive,
            database = database,
            s3_prefix = 'service=software',
            table_name = 'software_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'host',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'host_p',
                    type = _glue.Schema.SMALL_INT
                ),
                _glue.Column(
                    name = 'name',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'software_type',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'unparsed_version',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'version.addl',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'version.major',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'version.minor',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'version.minor2',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'version.minor3',
                    type = _glue.Schema.BIG_INT
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### SSL LOG ###

        ssl =  _glue.Table(
            self, 'ssl',
            bucket = archive,
            database = database,
            s3_prefix = 'service=ssl',
            table_name = 'ssl_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'version',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'cipher',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'curve',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'server_name',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'resumed',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'last_alert',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'next_protocol',
                    type = _glue.Schema.BINARY # _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'established',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'cert_chain_fuids',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'client_cert_chain_fuids',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'subject',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'issuer',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'client_subject',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'client_issuer',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'validation_status',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### STATS LOG ###

        stats =  _glue.Table(
            self, 'stats',
            bucket = archive,
            database = database,
            s3_prefix = 'service=stats',
            table_name = 'stats_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'active_dns_requests',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'active_files',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'active_icmp_conns',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'active_tcp_conns',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'active_timers',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'active_udp_conns',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'bytes_recv',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'dns_requests',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'events_proc',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'events_queued',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'files',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'icmp_conns',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'mem',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'peer',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'pkt_lag',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'pkts_dropped',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'pkts_link',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'pkts_proc',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'reassem_file_size',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'reassem_frag_size',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'reassem_tcp_size',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'reassem_unknown_size',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'tcp_conns',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'timers',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'udp_conns',
                    type = _glue.Schema.BIG_INT
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### TUNNEL LOG ###

        tunnel =  _glue.Table(
            self, 'tunnel',
            bucket = archive,
            database = database,
            s3_prefix = 'service=tunnel',
            table_name = 'tunnel_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'tunnel_type',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'action',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### WEIRD LOG ###

        weird =  _glue.Table(
            self, 'weird',
            bucket = archive,
            database = database,
            s3_prefix = 'service=weird',
            table_name = 'weird_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'uid',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.orig_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'id.resp_h',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'id.resp_p',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'name',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'addl',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'notice',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'peer',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'source',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### X509 LOG ###

        x509 =  _glue.Table(
            self, 'x509',
            bucket = archive,
            database = database,
            s3_prefix = 'service=x509',
            table_name = 'x509_'+vpc_id.replace('-','_'),
            columns = [
                _glue.Column(
                    name = 'id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.version',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'certificate.serial',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.subject',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.issuer',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.not_valid_before',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'certificate.not_valid_after',
                    type = _glue.Schema.TIMESTAMP
                ),
                _glue.Column(
                    name = 'certificate.key_alg',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.sig_alg',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.key_type',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.key_length',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'certificate.exponent',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'certificate.curve',
                    type = _glue.Schema.BINARY # _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'san.dns',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'san.uri',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'san.email',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'san.ip',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'basic_constraints.ca',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'basic_constraints.path_len',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'ts',
                    type = _glue.Schema.TIMESTAMP
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'siphon',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )
