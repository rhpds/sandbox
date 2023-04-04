#!/usr/bin/env python3
#
# Copyright 2023 Red Hat Inc. Guillaume Core (fridim) gucore at redhat.com
#
#
# This program sets up the sandbox-replicate lambda function.
# It creates a role, a policy and a lambda function.
# It also attaches the policy to the role and the role to the lambda function.
# It also push the updated 'build/sandbox-replicate' binary to the lambda function.

import json
import logging
import boto3
import botocore
import argparse
import os
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
iam = boto3.resource('iam')

def set_default_table():
    # Get env variable AWS_PROFILE
    profile = os.environ.get('AWS_PROFILE')

    if '-dev' in profile:
        return 'accounts-dev'
    return 'accounts'

def get_account_id():
    sts = boto3.client('sts')
    return sts.get_caller_identity().get('Account')

def get_role(role_name):
    """
    Gets a role by name.

    :param role_name: The name of the role to retrieve.
    :return: The specified role.
    """
    try:
        role = iam.Role(role_name)
        role.load()  # calls GetRole to load attributes
        logger.info("Got role with arn %s.", role.arn)
    except ClientError:
        logger.exception("Couldn't get role named %s.", role_name)
        raise
    else:
        return role

# Create role lambda-sandbox-replicate-role

def create_role(role_name, region, account, table):
    """
    Creates a role that lets a list of specified services assume the role.

    :param role_name: The name of the role.
    :param allowed_services: The services that can assume the role.
    :return: The newly created role.
    """
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            },
        ]
    }

    try:
        role = get_role(role_name)
        logger.info("Got role %s.", role.name)

        # Detach all policies
        for policy in role.attached_policies.all():
            role.detach_policy(PolicyArn=policy.arn)
            logger.info("Detached policy %s from role %s.", policy.arn, role.name)

        iam.Role(role_name).delete()
        logger.info("Deleted role %s.", role_name)
    except ClientError:
        logger.exception("Couldn't delete role %s.", role_name)
        raise

    try:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy))
        logger.info("Created role %s.", role.name)
    except ClientError:
        logger.exception("Couldn't create role %s.", role_name)
        raise

    # Attach policy to role
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:DescribeStream",
                    "dynamodb:GetRecords",
                    "dynamodb:GetShardIterator",
                    "dynamodb:ListStreams"
                ],
                "Resource": "arn:aws:dynamodb:%s:%s:table/%s/stream/*" %(region, account, table)
            },
        ]
    }



    try:

        role.attach_policy(
            PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
        logger.info("Attached Basic Execution Role policy to role %s.", role.name)

        # Delete policy
        iam.Policy('arn:aws:iam::%s:policy/lambda-sandbox-replicate-dynamodb-policy' % account).delete()
        logger.info("Deleted policy %s.", 'arn:aws:iam::%s:policy/lambda-sandbox-replicate-dynamodb-policy' % account)

        # Create policy
        policy = iam.create_policy(
            PolicyName='lambda-sandbox-replicate-dynamodb-policy',
            PolicyDocument=json.dumps(policy))
        logger.info("Created policy %s.", policy.arn)


        role.attach_policy(
            PolicyArn='arn:aws:iam::%s:policy/lambda-sandbox-replicate-dynamodb-policy' % account)

        logger.info("Attached DynamoDB policy to role %s.", role.name)
    except ClientError:
        logger.exception("Couldn't attach policy to role %s.", role.name)
        raise

    return role



# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', help='The AWS region that contains the DynamoDB table.', default='us-east-1')
    parser.add_argument('--account', help='The AWS account that contains the DynamoDB table.', default=get_account_id())
    parser.add_argument('--table', help='The DynamoDB table to replicate.', default=set_default_table())
    parser.add_argument('--zip-file', help='The App zip file.', default='./deploy/lambda/sandbox-replicate.zip')
    return parser.parse_args()

# Create lambda function sandbox-replicate

def create_lambda_function(function_name, region, role, zip_file):
    """
    Creates a Lambda function.

    :param function_name: The name of the function.
    :param role: The role to use for the function.
    :param zip_file: The zip file containing the function code.
    :return: The newly created function.
    """
    lambda_client = boto3.client('lambda', region_name=region)
    # Get function
    try:
        if lambda_client.get_function(FunctionName=function_name):
            lambda_client.delete_function(FunctionName=function_name)
            logger.info("Deleted Lambda function %s.", function_name)
    except ClientError:
        pass

    try:
        lambda_client.create_function(
            FunctionName=function_name,
            Runtime='go1.x',
            Handler='build/sandbox-replicate',
            Role=role.arn,
            Code={
                'ZipFile': open(zip_file, 'rb').read()
            },
            Timeout=300,
            MemorySize=128,
            Publish=True)
        logger.info("Created Lambda function %s.", function_name)

    except ClientError:
        logger.exception("Couldn't create Lambda function %s.", function_name)
        raise

parser = parse_args()

create_role('lambda-sandbox-replicate-role', parser.region, parser.account, parser.table)

create_lambda_function('sandbox-replicate',
                       parser.region,
                       get_role('lambda-sandbox-replicate-role'),
                       parser.zip_file)
