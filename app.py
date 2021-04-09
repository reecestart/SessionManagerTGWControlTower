#!/usr/bin/env python3

from enum import auto
from aws_cdk import (
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_secretsmanager as secretsmanager,
    aws_iam as iam,
    aws_autoscaling as autoscaling,
    aws_glue as glue,
    core,
)

from session_manager_tgw_control_tower.session_manager_tgw_control_tower_stack import SessionManagerTgwControlTowerStack

class SessionManagerTgwControlTowerStack(core.Stack):
    def __init__(self, app: core.App, id: str, **kwargs) -> None:
        super().__init__(app, id, **kwargs)

        vpc = ec2.Vpc(
            self, "VPC",
            max_azs=3,
            cidr='10.0.0.0/16',
            enable_dns_hostnames=True,
            enable_dns_support=True,
            subnet_configuration= [
                ec2.SubnetConfiguration(
                    name='DBSubnet',
                    subnet_type=ec2.SubnetType.ISOLATED,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name='Application-A',
                    subnet_type=ec2.SubnetType.PRIVATE,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name='Application-B',
                    subnet_type=ec2.SubnetType.PRIVATE,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name='Web',
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
            ]
        )

        dbSecurityGroup = ec2.SecurityGroup(
            self, 
            id= "dbSecurityGroup",
            vpc=vpc,
            security_group_name="DBSecurityGroup"
        )

        dbSubnetGroup = rds.SubnetGroup(
            self, "dbSubnetGroup",
            subnet_group_name="dbSubnetGroup",
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.ISOLATED),
            description="dbSubnetGroup",
            vpc=vpc
        )

        dbPassword = secretsmanager.Secret(
            self, "dbPassword",
            description="dbPassword",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=30,
                secret_string_template='{"username": "dbAdmin"}',
                generate_string_key="password",
                exclude_characters='"@\\\/',
                exclude_punctuation=True
            ),
            secret_name="dbPassword"
        )
        credentials=rds.Credentials.from_secret(dbPassword)

        db = rds.DatabaseInstance(
            self, "db",
            database_name="db1",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_11_5
            ),
            vpc=vpc,
            port=5432,
            instance_type= ec2.InstanceType.of(
                ec2.InstanceClass.STANDARD5,
                ec2.InstanceSize.LARGE,
            ),
            removal_policy=core.RemovalPolicy.DESTROY,
            deletion_protection=False,
            multi_az=True,
            publicly_accessible=False,
            security_groups=[dbSecurityGroup],
            subnet_group=dbSubnetGroup,
            credentials=credentials,
            enable_performance_insights=True
        )

        db.add_proxy(
            "DBProxy",
            vpc=vpc,
            secrets=[dbPassword],
            security_groups=[dbSecurityGroup]
        )

        RHELASG = autoscaling.AutoScalingGroup(
            self, "RHELASG",
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3_AMD,
                ec2.InstanceSize.SMALL
            ),
            machine_image=ec2.MachineImage.generic_linux(
                ami_map={
                    'ap-southeast-2': 'ami-044c46b1952ad5861', #RHEL
                    'ap-southeast-1': 'ami-0f86a70488991335e'
                }
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE),
            user_data=ec2.UserData.custom('\n'.join([
                "#!/bin/bash",
                "yum install python3 -y",
                "dnf install -y https://s3.ap-southeast-2.amazonaws.com/amazon-ssm-ap-southeast-2/latest/linux_amd64/amazon-ssm-agent.rpm",
                "dnf install -y https://s3.ap-southeast-1.amazonaws.com/amazon-ssm-ap-southeast-1/latest/linux_amd64/amazon-ssm-agent.rpm",
                "systemctl enable amazon-ssm-agent",
                "systemctl start amazon-ssm-agent",
                "yum install -y postgresql",
                "yum install -y git",
                "yum update -y",
                "cd /home/ec2-user",
                "DIR=\"aws-database-migration-samples\"",
                "if [ ! -d \"$DIR\" ]; then",
                "git clone https://github.com/aws-samples/aws-database-migration-samples.git",
                "fi",
                "cd aws-database-migration-samples/PostgreSQL/sampledb/v1/",
                "kill -9 16673",
                "dnf install python2-pip -y",
                "dnf install python3-pip -y",
                "pip2 --version",
                "pip3 --version",
                "cd /home/ec2-user",
                "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'",
                "yum install zip unzip -y",
                "unzip awscliv2.zip",
                "./aws/install -i /usr/local/aws-cli -b /usr/local/bin",
                "/usr/local/bin/aws --version",
                "DBDETAILS=`/usr/local/bin/aws rds describe-db-instances`",
                "sudo yum install jq -y",
                "DBIDENTIFIER=$(echo $DBDETAILS | jq -r '.[\"DBInstances\"][0][\"DBInstanceIdentifier\"]')",
                "/usr/local/bin/aws rds wait db-instance-available --db-instance-identifier $DBIDENTIFIER",
                "SECRETSTRING=`/usr/local/bin/aws secretsmanager get-secret-value --secret-id dbPassword --query SecretString --output text`",
                "PGPASSWORD=$(echo $SECRETSTRING | jq -r '.[\"password\"]')",
                "PGUSER=$(echo $SECRETSTRING | jq -r '.[\"username\"]')",
                "DBPROXY=`/usr/local/bin/aws rds describe-db-proxies`",
                "PROXYENDPOINT=$(echo $DBPROXY | jq -r '.[\"DBProxies\"][0][\"Endpoint\"]')",
                "PGDATABASE=$(echo $SECRETSTRING | jq -r '.[\"dbname\"]')",
                "PGPORT=$(echo $SECRETSTRING | jq -r '.[\"port\"]')",
                "cd /home/ec2-user",
                "cd aws-database-migration-samples/PostgreSQL/sampledb/v1/",
                "PGHOST=${PROXYENDPOINT} PGPORT=${PGPORT} PGDATABASE=${PGDATABASE} PGUSER=${PGUSER} PGPASSWORD=${PGPASSWORD} psql -f install-postgresql.sql"
                ])),
            desired_capacity=1,
            min_capacity=1,
            max_capacity=2
        )

        RHELASG.node.add_dependency(db)

        dbSecurityGroup.connections.allow_from(
            other=RHELASG,
            port_range=ec2.Port.tcp(5432),
            description="Allow pg connection from AppInstance"
        )

        RHELASG.role.add_managed_policy(
            policy=iam.ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonSSMManagedInstanceCore"
            )
        )

        RHELASG.role.add_managed_policy(
            policy=iam.ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonRDSFullAccess"
            )
        )

        RHELASG.role.add_managed_policy(
            policy=iam.ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="SecretsManagerReadWrite"
            )
        )

        S3Endpoint = ec2.GatewayVpcEndpointAwsService(
            name="S3"
        )



app = core.App()
SessionManagerTgwControlTowerStack(app, "session-manager-tgw-control-tower")

app.synth()
