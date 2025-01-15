#!/usr/bin/env python3

# First, grab the list of all sandboxes

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
import requests
import time
from ansible_vault import Vault

START_TIME = time.time()

#structlog.configure(
    #processors=[
        #structlog.stdlib.filter_by_level,
        #structlog.processors.TimeStamper(fmt="iso"),
        #structlog.processors.JSONRenderer()],
    #context_class=dict, logger_factory=structlog.stdlib.LoggerFactory())

logger = structlog.get_logger()
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))

# args: --reservation reservation_name

# parse the args

parser = argparse.ArgumentParser(description='Create a new sandbox')
parser.add_argument('--reservation', required=False, help='The reservation name', default='new')
parser.add_argument('--target-db', required=False, help='The target database', default='dev')
parser.add_argument('--log-level', required=False, help='The log level', default='info')
parser.add_argument('--retry', required=False, help='Retry sandbox by passing its name', default=None)
parser.add_argument('--playbook-output', required=False, help='Print output of ansible-playbook commands?', action=argparse.BooleanOptionalAction, default=True)

args = parser.parse_args()

reservation = args.reservation
logger = logger.bind(reservation=reservation)
target_db = args.target_db
log_level = args.log_level
retry = args.retry
playbook_output = args.playbook_output

if log_level == 'debug':
    logger.info("Setting log level to DEBUG")
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG))

logger.debug(f"Reservation: {reservation}")

# Make sure all environment variables are set

# Set default values for the environment variables
os.environ.setdefault('ddns_key_name', 'mydynamickey')
os.environ.setdefault('ddns_key_algorithm', 'hmac-sha512')
os.environ.setdefault('ddns_ttl', '600')
os.environ.setdefault('email_domain', 'opentlc.com')
# set default to ~/.aws/credentials_create
os.environ.setdefault('AWS_SHARED_CREDENTIALS_FILE', os.path.expanduser('~/.aws/credentials_create'))
# Create directory if it doesn't exist, chmod 700
logger.info(f"Creating directory {os.path.dirname(os.environ['AWS_SHARED_CREDENTIALS_FILE'])}")
os.makedirs(os.path.dirname(os.environ['AWS_SHARED_CREDENTIALS_FILE']), exist_ok=True)
os.chmod(os.path.dirname(os.environ['AWS_SHARED_CREDENTIALS_FILE']), 0o700)


required_env_vars = [
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_ACCESS_KEY_ID_DEV',
    'AWS_SECRET_ACCESS_KEY_DEV',
    'INFRA_VAULT_SECRET_DEV',
    'INFRA_VAULT_SECRET_PROD',
    'ddns_server',
    'ddns_key_secret',
    'RH_USERNAME',
    'RH_PASSWORD',
]

# constants: Steps

# step '0 - created in DB only'

STAGE0 = '0 - created in DB only'
STAGE1_STARTED = "1 - Account Creation Started"
STAGE1_FAILED = "1 - Account Creation Failed"
STAGE2_ACCOUNT_CREATED = "2 - Account Created"
STAGE3_GOLD_IMAGE = "3 - Gold Image Enabled"
STAGE4_VALIDATED = "4 - Account Validated and Ready"


for env_var in required_env_vars:
    if not os.environ.get(env_var):
        logger.info(f"Environment variable {env_var} not set")
        sys.exit(1)



session_prod = boto3.Session(region_name='us-east-1')
dynamodb_prod = session_prod.client('dynamodb')

session_dev = boto3.Session(region_name='us-east-1',
                            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID_DEV'],
                            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY_DEV'])
dynamodb_dev = session_dev.client('dynamodb')

# Set the target database
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

# Create temporary file using tempfile with the INFRA_VAULT_SECRET as content, with mode 700

with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write(os.environ['INFRA_VAULT_SECRET'])
    INFRA_VAULT_SECRET_FILE = f.name
    logger.info(f"Created temporary file {INFRA_VAULT_SECRET_FILE}")

# run `sandbox-list -all --sort name`

response = dynamodb_dev.scan(
    TableName='accounts-dev',
    ConsistentRead=True,
    ProjectionExpression='#n',
    ExpressionAttributeNames={
        '#n': 'name'
    }
)

if response['ResponseMetadata']['HTTPStatusCode'] != 200:
    logger.error("Failed to get items from dynamodb")
    sys.exit(1)

data = response['Items']
while 'LastEvaluatedKey' in response:
    response = dynamodb_dev.scan(
        TableName='accounts-dev',
        ConsistentRead=True,
        ProjectionExpression='#n',
        ExpressionAttributeNames={'#n': 'name'},
        ExclusiveStartKey=response['LastEvaluatedKey']
    )
    data.extend(response['Items'])

if 'Items' in response:
    sandboxes = [item['name']['S'] for item in data]
    logger.info(f"Found {len(sandboxes)} sandboxes in dev")

# Now run the command for the prod database

response = dynamodb_prod.scan(
    TableName='accounts',
    ConsistentRead=True,
    ProjectionExpression='#n',
    ExpressionAttributeNames={'#n': 'name'}
)

if response['ResponseMetadata']['HTTPStatusCode'] != 200:
    logger.error("Failed to get items from dynamodb")
    sys.exit(1)

data = response['Items']

while 'LastEvaluatedKey' in response:
    response = dynamodb_prod.scan(
        TableName='accounts',
        ConsistentRead=True,
        ProjectionExpression='#n',
        ExpressionAttributeNames={'#n': 'name'},
        ExclusiveStartKey=response['LastEvaluatedKey']
    )
    data.extend(response['Items'])

if 'Items' in response:
    sandboxes_prod = [item['name']['S'] for item in data]
    logger.info(f"Found {len(sandboxes_prod)} sandboxes in prod")
    sandboxes = sandboxes + sandboxes_prod

# transform into a dictionary
sandboxes_dict = {sandbox: True for sandbox in sandboxes}

def set_(dynamodb, sandbox, key, value):
    '''Set the key value pair in the DB'''
    response = dynamodb.update_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': sandbox
            }
        },
        UpdateExpression='SET #k = :val1',
        ExpressionAttributeNames={
            '#k': key
        },
        ExpressionAttributeValues={
            ':val1': {
                'S': value
            }
        }
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise Exception(f"Failed to set {key} to {value}")

def set_stage(dynamodb, sandbox, stage):
    """Set the stage of the sandbox"""
    response = dynamodb.update_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': sandbox
            }
        },
        UpdateExpression='SET #s = :val1',
        ExpressionAttributeNames={
            '#s': 'stage'
        },
        ExpressionAttributeValues={
            ':val1': {
                'S': stage
            }
        }
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise Exception(f"Failed to set the stage to {stage}")

def get_stage(dynamodb, sandbox):
    """Get the stage of the sandbox"""
    response = dynamodb.get_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': sandbox
            }
        }
    )

    if 'Item' in response:
        return response['Item'].get('stage', {}).get('S', '')
    else:
        return ''

def get_sandbox(dynamodb, sandbox):
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


def extract_sandbox_number(sandbox):
    """Extract the number from the sandbox name, for example sandbox1234 returns 1234"""
    return int(sandbox.split('sandbox')[1])


def guess_next_sandbox(sandboxes, sandboxes_dict):
    """Find the first available sandbox name"""
    # Generate a random email tag sandbox1+RANDSTR@opentlc.com
    # used when we reuse the account name. For some reason, the email is still registered
    # in AWS and we need to use a different email address even if the previous account is closed.
    random_email_tag = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))

    if retry:
        return retry, f"{retry}+{random_email_tag}@{os.environ['email_domain']}"
    for i in range(1, len(sandboxes) + 1):
        if not sandboxes_dict.get(f"sandbox{i}", False):
            return f"sandbox{i}", f"sandbox{i}+{random_email_tag}@{os.environ['email_domain']}"

    s = f"sandbox{extract_sandbox_number(sandboxes[-1]) + 1}"
    return s, f"{s}+{random_email_tag}@{os.environ['email_domain']}"


def decrypt_vaulted_str(secret):
    '''Decrypt the vaulted secret'''
    return Vault(os.environ['INFRA_VAULT_SECRET']).load_raw(secret).decode('utf-8')

new_sandbox, new_email = guess_next_sandbox(sandboxes, sandboxes_dict)
logger.info(f"=> Create {new_sandbox}")


# Lock the name of the sandbox in DB so another
# concurrent process won't be able to create the same sandbox.
sandbox_data = get_sandbox(dynamodb, new_sandbox)
if sandbox_data:
    stage = sandbox_data.get('stage', {}).get('S', '')
    if not retry:
        logger.info(f"Sandbox {new_sandbox} already exists")
        sys.exit(1)

    # Ensure the sandbox is not in use, available should be absent or true
    if retry:
        if sandbox_data.get('available', {}).get('BOOL', True) is False:
            logger.info(f"Retry {new_sandbox}")
        else:
            logger.error(f"{new_sandbox} is not available")
            sys.exit(1)

        if not stage:
            logger.error(f"Failed to get the stage for {new_sandbox}")
            sys.exit(1)

        creation_status = sandbox_data.get('creation_status', {}).get('S', '')

        if not creation_status:
            logger.error(f"Failed to get the creation_status for {new_sandbox}")
            sys.exit(1)


def lock_sandbox(dynamodb, sandbox):
    '''Lock the sandbox name'''
    item = {
        'name': {
            'S': new_sandbox
        },
        'available': {
            'BOOL': False
        },
        'to_cleanup': {
            'BOOL': False
        },
        'reservation': {
            'S': 'untested'
        },
        'comment': {
            'S': 'Creating new sandbox'
        },
        'stage': {
            'S': STAGE0
        },
        'creation_status': {
            'S': 'in progress'
        }
    }

    response = dynamodb.put_item(
        TableName=dynamodb_table,
        # If retry, no condition is needed
        ConditionExpression='attribute_not_exists(#n)' if not retry else 'attribute_exists(#n) or attribute_not_exists(#n)',
        ExpressionAttributeNames={
            '#n': 'name'
        },
        Item=item
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        logger.error("Failed to lock the sandbox name")
        sys.exit(1)

    logger.info(f"Locked {new_sandbox}")

lock_sandbox(dynamodb, new_sandbox)

def exit_handler(db, table, sandbox):
    '''Function to cleanup everything in case something went wrong'''

    # Delete INFRA_VAULT_SECRET_FILE

    os.remove(INFRA_VAULT_SECRET_FILE)

    # Check if the stage is STAGE0
    stage = get_stage(db, sandbox)
    if stage in [ STAGE0, STAGE1_FAILED ]:
        response = db.delete_item(
            TableName=table,
            Key={
                'name': {
                    'S': sandbox
                }
            }
        )

        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            logger.error(f"Failed to delete {sandbox}")
            sys.exit(1)
        else:
            logger.info(f"Deleted {sandbox}")
    elif stage == STAGE4_VALIDATED:
        pass
    else:
        # something went wrong
        logger.error(f"Unexpected stage: {stage}, missing validation")
        logger.info(f"You can retry the operation by running the command with --retry {sandbox}")
        set_(dynamodb, new_sandbox, 'creation_status', 'failed')
        sys.exit(1)

atexit.register(exit_handler, dynamodb, dynamodb_table, new_sandbox)

# Prepare the AWS profile for the ansible-playbook command
# - dynamodb   profile to manage the dynamodb table
# - pool-manager profile to manage the pool
# Save the file to AWS_SHARED_CREDENTIALS_FILE
if target_db == 'prod':
    with open(os.environ['AWS_SHARED_CREDENTIALS_FILE'], 'w') as f:
        f.write(
            f'''
[dynamodb]
aws_access_key_id = {os.environ['AWS_ACCESS_KEY_ID']}
aws_secret_access_key = {os.environ['AWS_SECRET_ACCESS_KEY']}
[pool-manager]
aws_access_key_id = {os.environ['AWS_ACCESS_KEY_ID']}
aws_secret_access_key = {os.environ['AWS_SECRET_ACCESS_KEY']}
'''
        )
else:
    with open(os.environ['AWS_SHARED_CREDENTIALS_FILE'], 'w') as f:
        f.write(
            f'''
[dynamodb]
aws_access_key_id = {os.environ['AWS_ACCESS_KEY_ID_DEV']}
aws_secret_access_key = {os.environ['AWS_SECRET_ACCESS_KEY_DEV']}
[pool-manager]
aws_access_key_id = {os.environ['AWS_ACCESS_KEY_ID']}
aws_secret_access_key = {os.environ['AWS_SECRET_ACCESS_KEY']}
            ''')

# Prepare args for the ansible-playbook command
#./create_range.yml -e account_num_start=3001 -e account_count=10 -e ddns_key_name=... -e ddns_key_secret=... -e ddns_server=...

local_path = os.path.dirname(os.path.realpath(__file__))
playbook = os.path.join(local_path, '..', 'playbooks', 'create_range.yml')

args = [
    'ansible-playbook',
    playbook,
    '-e', f'account_num_start={extract_sandbox_number(new_sandbox)}',
    '-e', f'account_email={new_email}',
    '-e', 'account_count=1',
    '-e', f'ddns_key_name={os.environ["ddns_key_name"]}',
    '-e', f'ddns_server={os.environ["ddns_server"]}',
    '-e', f'ddns_ttl={os.environ["ddns_ttl"]}',
    '-e', f'sandbox={new_sandbox}',
    '-e', 'update_stage=true',
    '-e', 'dynamodb_profile=dynamodb',
    '-e', f'dynamodb_table={dynamodb_table}',
    '-e', 'aws_master_profile=pool-manager',
    # Listing all accounts in the organization is a costly operation
    # it takes currently 47s to execute.
    # Check the account only in certain scenario, like for a retry
    '-e', f'check_account_list={True if retry else False}',
    '-e', f'vault_file={INFRA_VAULT_SECRET_FILE}',
]


# Run the command
logger.info(f"Running {' '.join(args)}")
# Add the ddns_key_secret to the args
args = args + ['-e', f'ddns_key_secret={os.environ["ddns_key_secret"]}']
try:
    completed = subprocess.run(
        args, check=True,
        capture_output=(not playbook_output),
        timeout=1800,
    )
except subprocess.CalledProcessError as e:
    # Sanitize the error message by removing the DDNS key secret
    e_sanitized = str(e).replace(os.environ['ddns_key_secret'], '***')
    logger.error(f"Failed to run the command: {e_sanitized}")
    # print stdout and stderr
    logger.error(e.stdout.decode(), stdout=True)
    logger.error(e.stderr.decode(), stderr=True)

    # Set sandbox status to failed
    response = dynamodb.update_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': new_sandbox
            }
        },
        UpdateExpression='SET #s = :val1',
        ExpressionAttributeNames={
            '#s': 'creation_status'
        },
        ExpressionAttributeValues={
            ':val1': {
                'S': 'failed'
            }
        }
    )

    sys.exit(1)
except subprocess.TimeoutExpired as e:
    # Sanitize the error message by removing the DDNS key secret
    e_sanitized = str(e).replace(os.environ['ddns_key_secret'], '***')
    logger.error(f"Timeout: {e_sanitized}", sandbox=new_sandbox)
    # Set sandbox status to failed
    response = dynamodb.update_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': new_sandbox
            }
        },
        UpdateExpression='SET #s = :val1',
        ExpressionAttributeNames={
            '#s': 'creation_status'
        },
        ExpressionAttributeValues={
            ':val1': {
                'S': 'failed'
            }
        }
    )
    sys.exit(1)

logger.info(f"Created {new_sandbox}")

# Get the account_id from the db

sandbox_data = get_sandbox(dynamodb, new_sandbox)

if sandbox_data:
    account_id = sandbox_data.get('account_id', {}).get('S', '')
    logger.info(f"Account ID: {account_id}")
    logger = logger.bind(account_id=account_id)

    # Write the account_id and the account name to cloud-automation/new_sandboxes.txt
    with open('cloud-automation/new_sandboxes.txt', 'w') as f:
        f.write(f"{new_sandbox} {account_id}\n")

set_(dynamodb, new_sandbox, 'stage', STAGE2_ACCOUNT_CREATED)
ACCOUNT_CREATED_TIME = time.time()
logger.info(f"Duration: {round(ACCOUNT_CREATED_TIME - START_TIME)} seconds to create {new_sandbox}")

# Use https://console.redhat.com/docs/api/sources/v3.1#operations-sources-bulkCreate

sandbox_data = get_sandbox(dynamodb, new_sandbox)

if not sandbox_data:
    logger.error(f"Failed to get the sandbox data for {new_sandbox}")
    sys.exit(1)

if 'aws_secret_access_key' not in sandbox_data:
    logger.error(f"Failed to get the aws_secret_access_key for {new_sandbox}")
    sys.exit(1)

plaintext_key = decrypt_vaulted_str(sandbox_data.get('aws_secret_access_key', {}).get('S', '')).strip(' \t\n\r')
access_key = sandbox_data.get('aws_access_key_id', {}).get('S', '').strip(' \t\n\r')

if not access_key or not plaintext_key:
    logger.error(f"Failed to get the access key for {new_sandbox}")
    sys.exit(1)

# use requests and create the POST request

baseurl = 'https://console.redhat.com/api/sources/v3.1'

s = requests.Session()
s.auth = (os.environ['RH_USERNAME'], os.environ['RH_PASSWORD'])

# delete the source if it exists
# First get the source_id
max_retries = 20
while True:
    response = s.get(f"{baseurl}/sources?filter[name][eq]={new_sandbox}")
    if response.status_code == 200:
        break
    logger.error(f"Failed to get the source: {response.text}", status_code=response.status_code, sandbox=new_sandbox)
    if max_retries == 0:
        sys.exit(1)

    logger.info(f"Retrying: {max_retries} retries left")
    max_retries -= 1
    time.sleep(5)

result = response.json().get('data', [])
if len(result) > 0:
    source_id = response.json().get('data', [{}])[0].get('id', '')

    if source_id:
        response = s.delete(f"{baseurl}/sources/{source_id}")
        if response.status_code not in [200, 201, 202]:
            logger.error(f"Failed to delete the source: {response.text}", status_code=response.status_code, sandbox=new_sandbox)

        logger.info(f"Deleted the source {source_id} for {new_sandbox}")

        # Wait for the deletion to complete
        max_retries = 20
        while max_retries > 0:
            response = s.get(f"{baseurl}/sources/{source_id}")
            if response.status_code == 404:
                break
            max_retries -= 1
            logger.info(f"Waiting for the source to be deleted from HCC (console): {max_retries} retries left")
            time.sleep(5)

        if max_retries == 0:
            logger.error(f"Failed to delete the source {source_id} for {new_sandbox}")
            sys.exit(1)

payload = {
    "sources": [
        {
            "name": new_sandbox,
            "source_type_name": "amazon",
            "app_creation_workflow": "account_authorization"
        }
    ],
    "authentications": [
        {
            "resource_type": "source",
            "resource_name": new_sandbox,
            "username": access_key,
            "password": plaintext_key,
            "authtype": "access_key_secret_key"
        }
    ],

    "applications": [
        {
            "source_name": new_sandbox,
            "application_type_name": "cloud-meter"
        }
    ]
}
response = s.post(f"{baseurl}/bulk_create", json=payload)

if response.status_code not in [200, 201]:
    logger.error(f"Failed to create the source: {response.text}", status_code=response.status_code, sandbox=new_sandbox)
    sys.exit(1)

# Run the validation playbook operation

local_path = os.path.dirname(os.path.realpath(__file__))
playbook = os.path.join(local_path, '..', 'playbooks', 'validate.yml')

args = [
    'ansible-playbook',
    playbook,
    '-e', f'account_num_start={extract_sandbox_number(new_sandbox)}',
    '-e', f'account_num_end={extract_sandbox_number(new_sandbox)}',
    '-e', f'sandbox={new_sandbox}',
    '-e', 'dynamodb_profile=dynamodb',
    '-e', f'dynamodb_table={dynamodb_table}',
    '-e', 'aws_master_profile=pool-manager',
    '-e', f'vault_file={INFRA_VAULT_SECRET_FILE}',
    '-e', 'operation=VALIDATE',
]

# Run the command
logger.info(f"Running {' '.join(args)}")

try:
    completed = subprocess.run(
        args, check=True,
        capture_output=(not playbook_output),
        timeout=1800,
    )

except subprocess.CalledProcessError as e:
    logger.error(f"Failed to run the command: {e}")
    # print stdout and stderr
    logger.error(e.stdout.decode(), stdout=True)
    logger.error(e.stderr.decode(), stderr=True)

    # Set sandbox status to validation failed
    response = dynamodb.update_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': new_sandbox
            }
        },
        UpdateExpression='SET #s = :val1',
        ExpressionAttributeNames={
            '#s': 'creation_status'
        },
        ExpressionAttributeValues={
            ':val1': {
                'S': 'validation failed'
            }
        }
    )

    sys.exit(1)

except subprocess.TimeoutExpired as e:
    logger.error(f"Timeout: {e}")
    # Set sandbox status to validation failed
    response = dynamodb.update_item(
        TableName=dynamodb_table,
        Key={
            'name': {
                'S': new_sandbox
            }
        },
        UpdateExpression='SET #s = :val1',
        ExpressionAttributeNames={
            '#s': 'creation_status'
        },
        ExpressionAttributeValues={
            ':val1': {
                'S': 'validation timed out'
            }
        }
    )
    sys.exit(1)

logger.info(f"Validation successful for {new_sandbox}")

# Move the sandbox to the final reservation

response = dynamodb.update_item(
    TableName=dynamodb_table,
    Key={
        'name': {
            'S': new_sandbox
        }
    },
    UpdateExpression='SET #r = :val1, #s = :val2, #c = :val3',
    ExpressionAttributeNames={
        '#r': 'reservation',
        '#s': 'stage',
        '#c': 'creation_status'
    },
    ExpressionAttributeValues={
        ':val1': {
            'S': reservation
        },
        ':val2': {
            'S': STAGE4_VALIDATED
        },
        ':val3': {
            'S': 'success'
        }
    }
)

if response['ResponseMetadata']['HTTPStatusCode'] != 200:
    logger.error("Failed to update the reservation")
    sys.exit(1)

logger.info(f"Moved {new_sandbox} to {reservation}")
logger.info(f"Total duration: {round(time.time() - START_TIME)} seconds")
