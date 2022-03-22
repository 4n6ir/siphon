import cdk_nag

from aws_cdk import (
    Aspects,
    CustomResource,
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_ec2 as _ec2,
    aws_events as _events,
    aws_events_targets as _targets,
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

        vpc_id = 'vpc-04eae279ceb94d7f6'    # <-- Enter VPC ID
        
        ec2_count = 1                       # <-- Enter EC2 Quantity
        
        ec2_type = 't3a.small'              # <-- Enter EC2 Size
        
        ebs_root = 8                        # <-- Enter Root Storage GBs

        ebs_data = 4                        # <-- Enter Data Storage GBs

################################################################################

        account = Stack.of(self).account
        region = Stack.of(self).region

### VPC ###

        vpc = _ec2.Vpc.from_lookup(
            self, 'vpc',
            vpc_id = vpc_id
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
    
        sgids = []
        sgids.append(monitor.security_group_id)

### SUBNET ###

        subnetids = []
        for subnet in vpc.public_subnets: # vpc.private_subnets
            subnetids.append(subnet.subnet_id)

### EC2 ###

        ### Ubuntu Server 20.04 LTS ###
        ubuntu = _ec2.MachineImage.generic_linux(
            {
                'us-east-1': 'ami-04505e74c0741db8d',
                'us-east-2': 'ami-0fb653ca2d3203ac1',
                'us-west-2': 'ami-0892d3c7ee96c0bf7'
            }
        )

        for subnetid in subnetids:
            subnet = _ec2.Subnet.from_subnet_id(
                self, subnetid,
                subnet_id = subnetid
            )
            for i in range(ec2_count):
                instance = _ec2.Instance(
                    self, 'instance-'+subnetid+'-'+str(i),
                    instance_type = _ec2.InstanceType(ec2_type),
                    machine_image = ubuntu,
                    vpc = vpc,
                    vpc_subnets = subnet,
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
                network = _ec2.CfnNetworkInterface(
                    self, 'instance-'+subnetid+'-'+str(i)+'-monitor',
                    subnet_id = subnetid,
                    group_set = sgids
                )
                attach = _ec2.CfnNetworkInterfaceAttachment(
                    self, 'instance-'+subnetid+'-'+str(i)+'-attach',
                    device_index = str(1),
                    instance_id = instance.instance_id,
                    network_interface_id = network.ref,
                    delete_on_termination = True
                )
                mirror = _ssm.StringParameter(
                    self, 'instance-'+subnetid+'-'+str(i)+'-mirror',
                    description = 'Siphon ENI Target Mirror(s)',
                    parameter_name = '/siphon/mirror/'+vpc_id+'/'+subnetid+'/instance'+str(i),
                    string_value = network.ref,
                    tier = _ssm.ParameterTier.STANDARD,
                )

### CDK NAG ###

        #Aspects.of(self).add(cdk_nag.AwsSolutionsChecks())