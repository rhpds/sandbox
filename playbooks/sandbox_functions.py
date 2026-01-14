#!/usr/bin/env python3

import os
from ansible_vault import Vault


def decrypt_vaulted_str(secret: str) -> str:
    '''Decrypt the vaulted secret (raw, no YAML parsing)'''
    vault = Vault(os.environ['INFRA_VAULT_SECRET'])
    # Ensure input is bytes if the library expects it
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    result = vault.load_raw(secret)
    # Decode bytes to string if needed
    if isinstance(result, bytes):
        return result.decode('utf-8')
    return result


def encrypt_vaulted_str(plaintext: str) -> str:
    '''Encrypt a string using ansible-vault format (raw, no YAML serialization)'''
    vault = Vault(os.environ['INFRA_VAULT_SECRET'])
    # Ensure input is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    result = vault.dump_raw(plaintext)
    # Return as string
    if isinstance(result, bytes):
        return result.decode('utf-8')
    return result


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

def get_random_sandbox(dynamodb, dynamodb_table):
    response = dynamodb.scan(
        TableName=dynamodb_table,
        ConsistentRead=True,
        # limit to 1 item
        Limit=1,
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise Exception("Failed to get items from dynamodb")

    data = response['Items']
    if len(data) == 0:
        raise Exception("No items found in dynamodb")

    return data[0]
