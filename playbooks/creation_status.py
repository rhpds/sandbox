#!/usr/bin/env python3


import subprocess
import os
import sys
import boto3
import argparse
import atexit
import structlog
import logging
import tempfile
import random
import string

logger = structlog.get_logger()
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))

session_prod = boto3.Session(region_name='us-east-1')
dynamodb_prod = session_prod.client('dynamodb')

session_dev = boto3.Session(region_name='us-east-1',
                            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID_DEV'],
                            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY_DEV'])
dynamodb_dev = session_dev.client('dynamodb')


def print_sandbox(item, db):
    if 'stage' not in item:
        return

    logger.info(item['name']['S'],
                creation_status=item.get('creation_status', {}).get('S', ''),
                stage= item.get('stage', {}).get('S', ''),
                available=item.get('available', {}).get('BOOL', ''),
                reservation= item.get('reservation', {}).get('S', ''),
                account_id=item.get('account_id', {}).get('S', ''),
                external_id=item.get('external_id', {}).get('S', ''),
                db=db)


response = dynamodb_dev.scan(
    TableName='accounts-dev',
    ConsistentRead=True,
)

if response['ResponseMetadata']['HTTPStatusCode'] != 200:
    logger.error("Failed to get items from dynamodb")
    sys.exit(1)

data = response['Items']
while 'LastEvaluatedKey' in response:
    response = dynamodb_dev.scan(
        TableName='accounts-dev',
        ConsistentRead=True,
        ExclusiveStartKey=response['LastEvaluatedKey']
    )
    data.extend(response['Items'])

if 'Items' in response:
    for item in data:
        print_sandbox(item, 'dev')

# Now run the command for the prod database

response = dynamodb_prod.scan(
    TableName='accounts',
    ConsistentRead=True,
)

if response['ResponseMetadata']['HTTPStatusCode'] != 200:
    logger.error("Failed to get items from dynamodb")
    sys.exit(1)

data = response['Items']

while 'LastEvaluatedKey' in response:
    response = dynamodb_prod.scan(
        TableName='accounts',
        ConsistentRead=True,
        ExclusiveStartKey=response['LastEvaluatedKey']
    )
    data.extend(response['Items'])

if 'Items' in response:
    for item in data:
        print_sandbox(item, 'prod')
