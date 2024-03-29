#!/usr/bin/env python3

import boto3
from boto3.dynamodb.types import TypeDeserializer
import sys


# Check that argument 'sandbox' is passed and capture it
if len(sys.argv) != 2:
    print("Usage: python3 migrate_aws_dynamodb_prod_to_dev.py sandbox")
    sys.exit(1)

sandbox = sys.argv[1]

# Create boto3 sessions for prod and dev
# use AWS_PROFILE pool-manager for prod and pool-manager-dev for dev

session_prod = boto3.Session(profile_name='pool-manager', region_name='us-east-1')
session_dev = boto3.Session(profile_name='pool-manager-dev', region_name='us-east-1')

# Create dynamodb clients
dynamodb_prod = session_prod.client('dynamodb')
dynamodb_dev = session_dev.client('dynamodb')



# Check that element exists in prod
try:
    response = dynamodb_prod.get_item(
        TableName='accounts',
        Key={
            'name': {
                'S': sandbox
            }
        }
    )
except Exception as e:
    print(e)
    sys.exit(1)


# Update item as not available with a comment

try:
    response = dynamodb_prod.update_item(
        TableName='accounts',
        Key={
            'name': {
                'S': sandbox
            }
        },
        UpdateExpression="set available = :false, to_cleanup = :false, #c = :comment",
        ExpressionAttributeNames={
            '#c': 'comment'
        },
        ExpressionAttributeValues={
            ':false': {
                'BOOL': False
            },
            ':true': {
                'BOOL': True
            },
            ':comment': {
                'S': 'Migrating from prod to dev'
            },
            ':inprogress': {
                'S': 'cleanup in progress'
            }
        },
        ConditionExpression="#c = :comment OR available = :true OR (to_cleanup = :true AND conan_status <> :inprogress)",
    )

except Exception as e:
    print(e)
    sys.exit(1)

# Copy the item from prod to dev

try:
    # Get item from prod
    response = dynamodb_prod.get_item(
        TableName='accounts',
        Key={
            'name': {
                'S': sandbox
            }
        }
    )

    # Convert dynamodb item to simple json
    #deserializer = TypeDeserializer()
    #python_data = {k: deserializer.deserialize(v) for k,v in response['Item'].items()}

    # Copy item to dev
    response = dynamodb_dev.put_item(
        TableName='accounts-dev',
        Item=response['Item'],
    )

    # Delete item from prod
    response = dynamodb_prod.delete_item(
        TableName='accounts',
        Key={
            'name': {
                'S': sandbox
            }
        }
    )

    # Mark new item for cleanup (dev)
    response = dynamodb_dev.update_item(
        TableName='accounts-dev',
        Key={
            'name': {
                'S': sandbox
            }
        },
        UpdateExpression="set to_cleanup = :true, #c = :comment",
        ExpressionAttributeNames={
            '#c': 'comment'
        },
        ExpressionAttributeValues={
            ':true': {
                'BOOL': True
            },
            ':comment': {
                'S': 'Migrating from prod to dev'
            }
        },
        ConditionExpression=" #c = :comment",
    )

except Exception as e:
    print(e)
    sys.exit(1)
