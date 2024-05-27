#!/usr/bin/env python3

# Create a default VPC if it does not exist


import boto3

ec2 = boto3.client('ec2')

# Create a default VPC if it does not exist

def create_vpc():
    vpc = ec2.create_default_vpc()
    print(vpc)
    return vpc


# Check if default VPC exists

def check_vpc():
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        if vpc['IsDefault']:
            return vpc['VpcId']
    return None

# Find the AMI ID for AWS Linux

def find_ami():
    images = ec2.describe_images(
        Filters=[
            {
                'Name': 'name',
                'Values': ['al2023-ami-2023.4.20240513.0-kernel-6.1-x86_64'],
            },
            {
                'Name': 'owner-id',
                'Values': ['137112412989'],
            }
        ],
    )

    for image in images['Images']:
        return image['ImageId']

    return None



if check_vpc() is None:
    create_vpc()

ami = find_ami()

if ami is None:
    print("AMI not found")
    exit(1)

instance = ec2.run_instances(
    ImageId=ami,
    InstanceType='t3.micro',
    MaxCount=1,
    MinCount=1,
    Monitoring={'Enabled': False},
)

print(instance)
