import os

from aws_cdk import (
    core,
    aws_ec2 as _ec2,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_ssm as _ssm,
)


vpc_id = 'vpc-<number>'
ec2_count = 1
ec2_type = 't3a.small'
ebs_gb = 8


class SiphonStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = os.environ['CDK_DEFAULT_ACCOUNT']
        region = os.environ['CDK_DEFAULT_REGION']
        bucket_name = 'siphon-'+account+'-'+region+'-'+vpc_id
        ssm_name = '/siphon/'+vpc_id+'/ssm'

        vpc = _ec2.Vpc.from_lookup(
            self, 'vpc',
            vpc_id = vpc_id
        )

        bucket = _s3.Bucket(
            self, 'bucket',
            bucket_name = bucket_name,
            encryption = _s3.BucketEncryption.KMS_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = core.RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True
        )

        ### Ubuntu Server 20.04 LTS ###
        ubuntu = _ec2.MachineImage.generic_linux(
            {
                'us-east-1': 'ami-042e8287309f5df03',
                'us-east-2': 'ami-08962a4068733a2b6',
                'us-west-2': 'ami-0ca5c3bd5a268e7db'
            }
        )

        role = _iam.Role(
            self, 'role',
            assumed_by = _iam.ServicePrincipal(
                'ec2.amazonaws.com'
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'AmazonSSMManagedInstanceCore'
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:ListBucket',
                    's3:GetBucketAcl',
                    's3:GetObject',
                    's3:PutObject'
                ],
                resources = [
                    bucket.bucket_arn,
                    bucket.arn_for_objects('*')
                ]
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'ec2:DescribeInstances'
                ],
                resources = [
                    '*'
                ]
            )
        )

        pcap = _ssm.StringParameter(
            self, 'pcap',
            parameter_name = '/siphon/'+vpc_id+'/bucket',
            string_value = bucket_name,
            tier = _ssm.ParameterTier.STANDARD
        )
        pcap.grant_read(role)

        management = _ec2.SecurityGroup(
            self, 'management',
            vpc = vpc,
            description = 'siphon-management-eni',
            allow_all_outbound = True
        )

        monitor = _ec2.SecurityGroup(
            self, 'monitor',
            vpc = vpc,
            description = 'siphon-monitor-eni',
            allow_all_outbound = True
        )
        monitor.add_ingress_rule(_ec2.Peer.any_ipv4(), _ec2.Port.udp(4789), 'siphon-monitor-eni')
    
        sgids = []
        sgids.append(monitor.security_group_id)

        subnetids = []
        for subnet in vpc.public_subnets:
            subnetids.append(subnet.subnet_id)

        instanceids = []
        for i in range(ec2_count):
            instance = _ec2.Instance(
                self, 'instance'+str(i),
                instance_type = _ec2.InstanceType(ec2_type),
                machine_image = ubuntu,
                vpc = vpc,
                role = role,
                security_group = management,
                block_devices = [
                    _ec2.BlockDevice(
                        device_name = '/dev/sda1',
                        volume = _ec2.BlockDeviceVolume.ebs(
                            ebs_gb,
                            encrypted = True
                        )
                    )
                ]
            )
            instanceids.append(instance.instance_id)
            eni_count = 0
            eni_index = 1
            for id in subnetids:
                network = _ec2.CfnNetworkInterface(
                    self, 'instance'+str(i)+'eni'+str(eni_count),
                    subnet_id = id,
                    group_set = sgids
                )
                attach = _ec2.CfnNetworkInterfaceAttachment(
                    self, 'instance'+str(i)+'eni'+str(eni_count)+'attach',
                    device_index = str(eni_index),
                    instance_id = instance.instance_id,
                    network_interface_id = network.ref,
                    delete_on_termination = True
                )
                eni_count += 1
                eni_index += 1

        config = _iam.Role(
            self, 'config', 
            assumed_by = _iam.ServicePrincipal(
                'lambda.amazonaws.com'
            )
        )
        
        config.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )
        
        config.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'ec2:DescribeInstances',
                    'events:DisableRule',
                    'ssm:GetParameter',
                    'ssm:SendCommand'
                ],
                resources = [
                    '*'
                ]
            )
        )

        compute = _lambda.Function(
            self, 'compute',
            code = _lambda.Code.from_asset('config'),
            handler = 'config.handler',
            runtime = _lambda.Runtime.PYTHON_3_8,
            timeout = core.Duration.seconds(30),
            role = config,
            environment = dict(
                INSTANCES = str(instanceids),
                PARAMETER = ssm_name
            ),
            memory_size = 128
        )

        logs = _logs.LogGroup(
            self, 'logs',
            log_group_name = '/aws/lambda/'+compute.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = core.RemovalPolicy.DESTROY
        )

        rule = _events.Rule(
            self, 'rule',
            schedule = _events.Schedule.cron(
                minute = '*',
                hour = '*',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )
        rule.add_target(_targets.LambdaFunction(compute))

        parameter = _ssm.StringParameter(
            self, 'parameter',
            parameter_name = ssm_name,
            string_value = rule.rule_name,
            tier = _ssm.ParameterTier.STANDARD
        )
