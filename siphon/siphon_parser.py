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
                name = 'siphon'
            )
        )

### CONN LOG ###

        conn = _glue.CfnTable(
            self, 'conn',
            catalog_id = account,
            database_name = 'siphon',
            table_input = _glue.CfnTable.TableInputProperty(
                name = 'conn',
                partition_keys = [
                    _glue.CfnTable.ColumnProperty(
                        name = 'year',
                        type = 'string'
                    ),
                    _glue.CfnTable.ColumnProperty(
                        name = 'month',
                        type = 'string'
                    ),
                    _glue.CfnTable.ColumnProperty(
                        name = 'day',
                        type = 'string'
                    ),
                    _glue.CfnTable.ColumnProperty(
                        name = 'host',
                        type = 'string'
                    )
                ],
                storage_descriptor = _glue.CfnTable.StorageDescriptorProperty(
                    input_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    location = 's3://'+archive_name+'/service=conn/',
                    output_format = 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    serde_info = _glue.CfnTable.SerdeInfoProperty(
                        serialization_library = 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe',
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
