#!/usr/bin/env python3

import os
from ansible_vault import Vault

def extract_sandbox_number(sandbox):
    """Extract the number from the sandbox name, for example sandbox1234 returns 1234"""
    return int(sandbox.split('sandbox')[1])

def get_sandbox(dynamodb, dynamodb_table, sandbox):
    """Get the sandbox from the DB"""
    response = dynamodb.get_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': sandbox
            }
        }
    )

    if 'Item' in response:
        return response['Item']
    else:
        return {}

def decrypt_vaulted_str(secret):
    '''Decrypt the vaulted secret'''
    return Vault(os.environ['INFRA_VAULT_SECRET']).load_raw(secret).decode('utf-8')

def get_all_sandboxes(dynamodb, dynamodb_table):
    response = dynamodb.scan(
        TableName=dynamodb_table,
        ConsistentRead=True,
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise Exception("Failed to get items from dynamodb")

    data = response['Items']
    while 'LastEvaluatedKey' in response:
        response = dynamodb.scan(
            TableName=dynamodb_table,
            ConsistentRead=True,
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
        data.extend(response['Items'])

    if 'Items' in response:
        sandboxes = data

    return sandboxes
