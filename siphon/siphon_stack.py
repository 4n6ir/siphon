import os

from aws_cdk import (
    CustomResource,
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_ec2 as _ec2,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_lambda_event_sources as _sources,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_s3_deployment as _deployment,
    aws_s3_notifications as _notifications,
    aws_sns as _sns,
    aws_sns_subscriptions as _subscriptions,
    aws_sqs as _sqs,
    aws_ssm as _ssm,
    custom_resources as _custom
)

from constructs import Construct

class SiphonStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

################################################################################

        vpc_id = 'vpc-0aa03892e4dcb8332'    # <-- Enter VPC ID
        
        ec2_count = 1                       # <-- Enter EC2 Quantity
        
        ec2_type = 't3a.small'              # <-- Enter EC2 Size
        
        ebs_root = 8                        # <-- Enter Root Storage GBs

        ebs_data = 4                        # <-- Enter Data Storage GBs

################################################################################

        account = Stack.of(self).account
        region = Stack.of(self).region
        
        bucket_name = 'siphon-'+account+'-'+region+'-'+vpc_id
        archive_name = 'siphon-parquet-'+account+'-'+region+'-'+vpc_id
        athena_name = 'siphon-athena-'+account+'-'+region+'-'+vpc_id

### DYNAMODB ###

        data = _dynamodb.Table(
            self, 'data',
            partition_key = {
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING
            },
            sort_key = {
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING
            },
            billing_mode = _dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy = RemovalPolicy.DESTROY,
            point_in_time_recovery = True
        )

        status = _ssm.StringParameter(
            self, 'status',
            description = 'Siphon Parser Status',
            parameter_name = '/siphon/dynamodb/data',
            string_value = data.table_name,
            tier = _ssm.ParameterTier.STANDARD,
        )

### S3 BUCKETS ###

        bucket = _s3.Bucket(
            self, 'bucket',
            bucket_name = bucket_name,
            encryption = _s3.BucketEncryption.KMS_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True
        )

        pcap = _ssm.StringParameter(
            self, 'pcap',
            description = 'Siphon Zeek Bucket',
            parameter_name = '/siphon/'+vpc_id+'/bucket',
            string_value = bucket_name,
            tier = _ssm.ParameterTier.STANDARD
        )

        athena = _s3.Bucket(
            self, 'athena',
            bucket_name = athena_name,
            encryption = _s3.BucketEncryption.KMS_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True
        )

### S3 DEPLOYMENT ###

        script_name = 'siphon-'+str(account)+'-scripts-'+region

        os.system('echo "#!/usr/bin/bash" > script/siphon.sh')
        
        os.system('echo "apt-get update" >> script/siphon.sh')
        os.system('echo "apt-get upgrade -y" >> script/siphon.sh')
        
        os.system('echo "apt-get install cmake gdb python3-pip unzip -y" >> script/siphon.sh')
        
        os.system('echo "wget https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -P /tmp/" >> script/siphon.sh')
        os.system('echo "unzip /tmp/awscli-exe-linux-x86_64.zip -d /tmp" >> script/siphon.sh')
        os.system('echo "/tmp/aws/install" >> script/siphon.sh')
        
        os.system('echo "aws s3 cp s3://'+script_name+'/patch-reboot.sh /root/patch-reboot.sh" >> script/siphon.sh')
        os.system('echo "chmod 750 /root/patch-reboot.sh" >> script/siphon.sh')
        
        os.system('echo "aws s3 cp s3://'+script_name+'/crontab.txt /tmp/crontab.txt" >> script/siphon.sh')
        os.system('echo "cat /tmp/crontab.txt >> /etc/crontab" >> script/siphon.sh')
        
        os.system('echo "DEBIAN_FRONTEND=noninteractive apt-get install postfix -y" >> script/siphon.sh')
        os.system('echo "echo \'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /\' | sudo tee /etc/apt/sources.list.d/security:zeek.list" >> script/siphon.sh')
        os.system('echo "curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null" >> script/siphon.sh')
        os.system('echo "apt-get update" >> script/siphon.sh')
        os.system('echo "apt-get install zeek-lts -y" >> script/siphon.sh')
        
        os.system('echo "add-apt-repository ppa:oisf/suricata-stable -y" >> script/siphon.sh')
        os.system('echo "apt-get update" >> script/siphon.sh')
        os.system('echo "apt-get install suricata -y" >> script/siphon.sh')
        
        os.system('echo "aws s3 cp s3://'+script_name+'/suricata.json /root/suricata.json" >> script/siphon.sh')
        os.system('echo "cd /tmp && wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" >> script/siphon.sh')
        os.system('echo "cd /tmp && dpkg -i amazon-cloudwatch-agent.deb" >> script/siphon.sh')
        os.system('echo "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/root/suricata.json" >> script/siphon.sh')

        os.system('echo "cd /tmp && git clone https://github.com/J-Gras/zeek-af_packet-plugin" >> script/siphon.sh')
        os.system('echo "cd /tmp/zeek-af_packet-plugin && export PATH=/opt/zeek/bin:$PATH && ./configure && make && make install" >> script/siphon.sh')
        os.system('echo "/opt/zeek/bin/zeek -NN Zeek::AF_Packet" >> script/siphon.sh')
        os.system('echo "setcap cap_net_raw+eip /opt/zeek/bin/zeek" >> script/siphon.sh')

        os.system('echo "pip3 install boto3 requests" >> script/siphon.sh')
        os.system('echo "aws s3 cp s3://'+script_name+'/siphon.py /tmp/siphon.py" >> script/siphon.sh')
        os.system('echo "/usr/bin/python3 /tmp/siphon.py" >> script/siphon.sh')

        script = _s3.Bucket(
            self, 'script',
            bucket_name = script_name,
            encryption = _s3.BucketEncryption.KMS_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True
        )

        scripts = _deployment.BucketDeployment(
            self, 'scripts',
            sources = [_deployment.Source.asset('script')],
            destination_bucket = script,
            prune = False
        )

### PARSER ###

        zeek = _iam.Role(
            self, 'zeek', 
            assumed_by = _iam.ServicePrincipal(
                'lambda.amazonaws.com'
            )
        )
        
        zeek.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )
        
        zeek.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'dynamodb:PutItem'
                ],
                resources = [
                    data.table_arn
                ]
            )
        )
        
        zeek.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetObject'
                ],
                resources = [
                    bucket.bucket_arn,
                    bucket.arn_for_objects('*')
                ]
            )
        )

        zeek.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:PutObject'
                ],
                resources = [
                    'arn:aws:s3:::'+archive_name,
                    'arn:aws:s3:::'+archive_name+'/*'
                ]
            )
        )

        parser = _lambda.DockerImageFunction(
            self, 'parser',
            code = _lambda.DockerImageCode.from_image_asset('parser'),
            timeout = Duration.seconds(900),
            role = zeek,
            environment = dict(
                DYNAMODB = data.table_name,
                S3BUCKET = bucket.bucket_name,
                S3ARCHIVE = archive_name
            ),
            memory_size = 4096
        )

        history = _logs.LogGroup(
            self, 'history',
            log_group_name = '/aws/lambda/'+parser.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        parsermonitor = _ssm.StringParameter(
            self, 'parsermonitor',
            description = 'Siphon Parser Monitor',
            parameter_name = '/siphon/monitor/parser',
            string_value = '/aws/lambda/'+parser.function_name,
            tier = _ssm.ParameterTier.STANDARD,
        )

        queue = _sqs.Queue(
            self, 'queue',
            visibility_timeout = Duration.seconds(1800)
        )
        
        queue.grant_consume_messages(parser)

        parser.add_event_source(
            _sources.SqsEventSource(
                queue = queue
            )
        )

        topic = _sns.Topic(
            self, 'topic'
        )
        
        topic.add_subscription(
            _subscriptions.SqsSubscription(
                queue,
                raw_message_delivery = True
            )
        )
        
        bucket.add_event_notification(
            _s3.EventType.OBJECT_CREATED, 
            _notifications.SnsDestination(topic)
        )

### IAM ###

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

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'CloudWatchAgentServerPolicy'
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

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'ssm:GetParameter'
                ],
                resources = [
                    pcap.parameter_arn
                ]
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetBucketAcl',
                    's3:GetBucketLocation',
                    's3:GetObject',
                    's3:ListBucket',
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
                    's3:GetObject'
                ],
                resources = [
                    script.bucket_arn,
                    script.arn_for_objects('*')
                ]
            )
        )

### VPC ###

        vpc = _ec2.Vpc.from_lookup(
            self, 'vpc',
            vpc_id = vpc_id
        )

### SG ###

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

### SUBNET ###

        subnetids = []
        for subnet in vpc.public_subnets: # vpc.private_subnets
            subnetid = {}
            subnetid['subnet_id'] = subnet.subnet_id
            subnetid['availability_zone'] = subnet.availability_zone
            subnetids.append(subnetid)

### EC2 ###

        ### Ubuntu Server 20.04 LTS ###
        ubuntu = _ec2.MachineImage.generic_linux(
            {
                'us-east-1': 'ami-08d4ac5b634553e16',
                'us-east-2': 'ami-0960ab670c8bb45f3',
                'us-west-2': 'ami-0ddf424f81ddb0720'
            }
        )

        instanceids = []
        for subnetid in subnetids:
            subnet = _ec2.Subnet.from_subnet_attributes(
                self, subnetid['subnet_id'],
                subnet_id = subnetid['subnet_id'],
                availability_zone = subnetid['availability_zone']
            )
            for i in range(ec2_count):
                instance = _ec2.Instance(
                    self, 'instance-'+subnetid['subnet_id']+'-'+str(i),
                    instance_type = _ec2.InstanceType(ec2_type),
                    machine_image = ubuntu,
                    vpc = vpc,
                    vpc_subnets = _ec2.SubnetSelection(
                        subnets = [subnet]
                    ),
                    role = role,
                    security_group = management,
                    require_imdsv2 = True,
                    propagate_tags_to_volume_on_creation = True,
                    block_devices = [
                        _ec2.BlockDevice(
                            device_name = '/dev/sda1',
                            volume = _ec2.BlockDeviceVolume.ebs(
                                ebs_root,
                                encrypted = True
                            )
                        ),
                        _ec2.BlockDevice(
                            device_name = '/dev/sdf',
                            volume = _ec2.BlockDeviceVolume.ebs(
                                ebs_data,
                                encrypted = True
                            )
                        )
                    ]
                )
                instanceids.append(instance.instance_id)
                network = _ec2.CfnNetworkInterface(
                    self, 'instance-'+subnetid['subnet_id']+'-'+str(i)+'-monitor',
                    subnet_id = subnet.subnet_id,
                    group_set = [
                        monitor.security_group_id
                    ],
                    interface_type = 'interface',
                    source_dest_check = False
                )
                attach = _ec2.CfnNetworkInterfaceAttachment(
                    self, 'instance-'+subnetid['subnet_id']+'-'+str(i)+'-attach',
                    device_index = str(1),
                    instance_id = instance.instance_id,
                    network_interface_id = network.ref,
                    delete_on_termination = True
                )
                mirror = _ssm.StringParameter(
                    self, 'instance-'+subnetid['subnet_id']+'-'+str(i)+'-mirror',
                    description = 'Siphon ENI Target Mirror(s)',
                    parameter_name = '/siphon/mirror/'+vpc_id+'/'+subnetid['subnet_id']+'/instance'+str(i),
                    string_value = network.ref,
                    tier = _ssm.ParameterTier.STANDARD,
                )

### CONFIGURATION ###

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
                    'ssm:SendCommand'
                ],
                resources = [
                    '*'
                ]
            )
        )

        configuration = _lambda.Function(
            self, 'configuration',
            code = _lambda.Code.from_asset('configuration'),
            handler = 'configuration.handler',
            runtime = _lambda.Runtime.PYTHON_3_9,
            timeout = Duration.seconds(30),
            environment = dict(
                INSTANCE = str(instanceids),
                SCRIPTS3 = script_name
            ),
            memory_size = 128,
            role = config
        )
       
        configlogs = _logs.LogGroup(
            self, 'configlogs',
            log_group_name = '/aws/lambda/'+configuration.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        configmonitor = _ssm.StringParameter(
            self, 'configmonitor',
            description = 'Siphon Config Monitor',
            parameter_name = '/siphon/monitor/config',
            string_value = '/aws/lambda/'+configuration.function_name,
            tier = _ssm.ParameterTier.STANDARD,
        )

        provider = _custom.Provider(
            self, 'provider',
            on_event_handler = configuration
        )

        resource = CustomResource(
            self, 'resource',
            service_token = provider.service_token
        )
