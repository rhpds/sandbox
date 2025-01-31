#!/usr/bin/env python3


import boto3
import time
import random
import logging
import os
import argparse
import structlog
from ansible_vault import Vault
from sandbox_functions import get_sandbox, decrypt_vaulted_str, get_all_sandboxes

START_TIME = time.time()
logger = structlog.get_logger()
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))

parser = argparse.ArgumentParser(description='Validate a sandbox')
parser.add_argument('--sandbox', required=False, help='sandbox to validate, by passing its name', default=None)
parser.add_argument('--reservation', required=False, help='reservation to validate, by passing its name', default=None)
parser.add_argument('--target-db', required=False, help='The target database', default='dev')
args = parser.parse_args()

required_env_vars = [
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_ACCESS_KEY_ID_DEV',
    'AWS_SECRET_ACCESS_KEY_DEV',
    'INFRA_VAULT_SECRET_DEV',
    'INFRA_VAULT_SECRET_PROD',
]

for env_var in required_env_vars:
    if not os.environ.get(env_var):
        logger.info(f"Environment variable {env_var} not set")
        sys.exit(1)

sandbox = args.sandbox
target_db = args.target_db
reservation = args.reservation

if not sandbox and not reservation:
    logger.error("Either sandbox or reservation is required")
    sys.exit(1)

# Set the target database
session_prod = boto3.Session(region_name='us-east-1')
dynamodb_prod = session_prod.client('dynamodb')

session_dev = boto3.Session(region_name='us-east-1',
                            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID_DEV'],
                            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY_DEV'])
dynamodb_dev = session_dev.client('dynamodb')
dynamodb_table = 'accounts-dev'
dynamodb = dynamodb_dev

if target_db == 'prod':
    logger.info("Using PROD dynamoDB database")
    dynamodb_table = 'accounts'
    dynamodb = dynamodb_prod
    logger = logger.bind(target_db='prod')
    os.environ['INFRA_VAULT_SECRET'] = os.environ['INFRA_VAULT_SECRET_PROD']
else:
    logger.info("Using DEV dynamoDB database")
    # bind context variable to the logger
    logger = logger.bind(target_db='dev')
    os.environ['INFRA_VAULT_SECRET'] = os.environ['INFRA_VAULT_SECRET_DEV']

#def find_rhel_amis(sandbox, account_id, aws_access_key_id, aws_secret_access_key):
def find_rhel_amis(sandbox, dynamodb, dynamodb_table):
    # List of possible regions
    regions = [
        'us-east-1',
        'us-east-2',
        'us-west-1',
        'us-west-2',
        'eu-central-1',
        'eu-west-1',
        'eu-west-2',
        'ap-southeast-1',
    ]

    sandbox_data = get_sandbox(dynamodb, dynamodb_table, sandbox)
    account_id = sandbox_data.get('account_id').get('S')
    aws_access_key_id = sandbox_data.get('aws_access_key_id').get('S').strip(' \t\n\r')
    aws_secret_access_key = decrypt_vaulted_str(sandbox_data.get('aws_secret_access_key').get('S')).strip(' \t\n\r')


    for region in regions:
        find_rhel_ami_in_region(sandbox, account_id, region, aws_access_key_id, aws_secret_access_key)

def find_rhel_ami_in_region(sandbox, account_id, region, aws_access_key_id, aws_secret_access_key):
    # Create an EC2 client
    ec2_client = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    # We'll try up to 150 times, sleeping 6 seconds each time (total of ~15 minutes)
    max_retries = 1
    delay = 6

    images = []
    for attempt in range(max_retries):
        try:
            response = ec2_client.describe_images(
                Owners=['309956199498'],
                Filters=[
                    {'Name': 'architecture', 'Values': ['x86_64']},
                    {'Name': 'name', 'Values': ['RHEL-9.0*Access*']},
                    {'Name': 'is-public', 'Values': ['false']}
                ]
            )
            images = response.get('Images', [])

            # If we got at least one image, break out of the loop
            if images:
                logger.info(f"Found {len(images)} matching image(s).", region=region, sandbox=sandbox, account_id=account_id)
                break

            logger.info(
                f"Attempt {attempt + 1}/{max_retries}: No matching images yet. Retrying in {delay} seconds...",
                region=region,
                sandbox=sandbox,
                account_id=account_id
            )
            if max_retries > 1:
                time.sleep(delay)

        except Exception as e:
            logger.error(f"Encountered an error: {e}", region=region, sandbox=sandbox, account_id=account_id)
            time.sleep(delay)

    # After the loop, check if we found images
    if not images:
        logger.error("No AMIs found after all retries.", region=region, sandbox=sandbox, account_id=account_id)

if __name__ == "__main__":
    # Get the credentials from dynamodb
    if sandbox:
        find_rhel_amis(sandbox, dynamodb, dynamodb_table)

    if reservation:
        sandboxes = get_all_sandboxes(dynamodb, dynamodb_table)

        for sandbox in sandboxes:
            if sandbox.get('reservation', {}).get('S', '') == reservation:
                find_rhel_amis(sandbox.get('name').get('S'), dynamodb, dynamodb_table)
