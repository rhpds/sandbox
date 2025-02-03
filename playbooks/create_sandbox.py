#!/usr/bin/env python3

import argparse
import atexit
import boto3
import hashlib
import json
import logging
import os
import random
import requests
import string
import structlog
import subprocess
import sys
import tempfile
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
parser.add_argument('--playbook', required=False, help='run the creation playbook?', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--hcc', required=False, help='run the registration step for Gold images?', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--validation', required=False, help='run the validation playbook?', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--guess-strategy', required=False, help='How to guess the next number: smart, end', default='end')

args = parser.parse_args()

reservation = args.reservation
logger = logger.bind(reservation=reservation)
target_db = args.target_db
log_level = args.log_level
retry = args.retry
playbook= args.playbook
playbook_output = args.playbook_output
hcc = args.hcc
validation = args.validation
guess_strategy = args.guess_strategy

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
os.environ.setdefault('REDHAT_ACCOUNT', '998366406740')
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
    'HCC_CLIENT_ID',
    'HCC_CLIENT_SECRET',
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


def extract_sandbox_number(sandbox):
    """Extract the number from the sandbox name, for example sandbox1234 returns 1234"""
    return int(sandbox.split('sandbox')[1])

def set_str(dynamodb, sandbox, key, value):
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

# TODO detect type instead of this _bool and _str
def set_bool(dynamodb, sandbox, key, value):
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
                'BOOL': value
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

def get_all_sandboxes(dynamodb_prod, dynamodb_dev):
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

    sandboxes.sort(key=extract_sandbox_number)

    return sandboxes



def guess_next_sandbox(dynamodb_prod, dynamodb_dev):
    """Find the first available sandbox name"""
    # Generate a random email tag sandbox1+RANDSTR@opentlc.com
    # used when we reuse the account name. For some reason, the email is still registered
    # in AWS and we need to use a different email address even if the previous account is closed.
    random_email_tag = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))

    if retry:
        return retry, f"{retry}+{random_email_tag}@{os.environ['email_domain']}"

    sandboxes = get_all_sandboxes(dynamodb_prod, dynamodb_dev)

    # transform into a dictionary
    sandboxes_dict = {sandbox: True for sandbox in sandboxes}

    if guess_strategy == 'smart':
        for i in range(1, len(sandboxes) + 1):
            if not sandboxes_dict.get(f"sandbox{i}", False):
                return f"sandbox{i}", f"sandbox{i}+{random_email_tag}@{os.environ['email_domain']}"

    logger.info(f"len(sanboxes) = {len(sandboxes)}")
    s = f"sandbox{extract_sandbox_number(sandboxes[-1]) + 1}"
    return s, f"{s}+{random_email_tag}@{os.environ['email_domain']}"


def decrypt_vaulted_str(secret):
    '''Decrypt the vaulted secret'''
    return Vault(os.environ['INFRA_VAULT_SECRET']).load_raw(secret).decode('utf-8')

new_sandbox, new_email = guess_next_sandbox(dynamodb_prod, dynamodb_dev)
logger = logger.bind(sandbox=new_sandbox)

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
        if sandbox_data.get('service_uuid', {}).get('S', '') == '':
            logger.info(f"Retry {new_sandbox}")
        else:
            logger.error(f"{new_sandbox} is not available")
            sys.exit(1)

        if not stage:
            logger.error(f"Failed to get the stage for {new_sandbox}")
            sys.exit(1)

        # creation_status = sandbox_data.get('creation_status', {}).get('S', '')

        # if not creation_status:
        #     logger.error(f"Failed to get the creation_status for {new_sandbox}")
        #     sys.exit(1)


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

def exit_handler(db, table, sandbox):
    '''Function to cleanup everything in case something went wrong'''

    # Delete INFRA_VAULT_SECRET_FILE

    os.remove(INFRA_VAULT_SECRET_FILE)

    # Check if the stage is STAGE0
    stage = get_stage(db, sandbox)
    if stage in [ STAGE0, STAGE1_STARTED, STAGE1_FAILED ]:
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
        if validation:
            # something went wrong
            logger.error(f"Unexpected stage: {stage}, missing validation")
            logger.info(f"You can retry the operation by running the command with --retry {sandbox}")
            set_str(dynamodb, new_sandbox, 'creation_status', 'failed')
            sys.exit(1)
        if hcc:
            if stage != STAGE3_GOLD_IMAGE:
                # something went wrong
                logger.error(f"Unexpected stage: {stage}, missing validation")
                logger.info(f"You can retry the operation by running the command with --retry {sandbox}")
                set_str(dynamodb, new_sandbox, 'creation_status', 'failed')
                sys.exit(1)


atexit.register(exit_handler, dynamodb, dynamodb_table, new_sandbox)


def get_sso_access_token():
    """ Create a session token using HCC_CLIENT_ID and HCC_CLIENT_SECRET"""

    # This is the standard Keycloak endpoint for client_credentials
    token_url = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    # Client Credentials Grant
    payload = {
        "grant_type": "client_credentials",
        "client_id": os.environ['HCC_CLIENT_ID'],
        "client_secret": os.environ['HCC_CLIENT_SECRET']
    }

    response = requests.post(token_url, data=payload)

    if response.status_code != 200:
        raise ValueError(f"Failed to obtain token: {response.status_code} {response.text}")


    # Parse out the access token
    access_token = response.json().get("access_token")
    if not access_token:
        raise ValueError("No access token found in the response")


    logger.info("Successfully obtained an access token for console.redhat.com.")
    return access_token

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

def assume_role(master_profile, role_arn, role_session_name, region_name='us-east-2'):
    """Assume a role using the master profile"""


    session = boto3.Session(profile_name=master_profile)
    sts = session.client('sts', region_name=region_name)

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=role_session_name
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise Exception("Failed to assume role")

    return response['Credentials']


if playbook:
    lock_sandbox(dynamodb, new_sandbox)

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

    set_str(dynamodb, new_sandbox, 'stage', STAGE2_ACCOUNT_CREATED)
    set_str(dynamodb, new_sandbox, 'reservation', 'untested')
    ACCOUNT_CREATED_TIME = time.time()
    logger.info(f"Duration: {round(ACCOUNT_CREATED_TIME - START_TIME)} seconds to create {new_sandbox}")


if hcc:
    # Use https://console.redhat.com/docs/api/sources/v3.1#operations-sources-bulkCreate

    sandbox_data = get_sandbox(dynamodb, new_sandbox)

    if not sandbox_data:
        logger.error(f"Failed to get the sandbox data for {new_sandbox}")
        sys.exit(1)

    if 'aws_secret_access_key' not in sandbox_data:
        logger.error(f"Failed to get the aws_secret_access_key for {new_sandbox}")
        sys.exit(1)


    account_id = sandbox_data.get('account_id', {}).get('S', '')
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"

    credentials = assume_role('pool-manager', role_arn, 'hcc-registration')

    if not credentials:
        logger.error("Failed to assume role", role_arn=role_arn)
        sys.exit(1)

    # create a new session with the assumed role credentials
    sandbox_session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name='us-east-1'
    )

    policy_name = 'redhat-HCC-policy'

    iam_client = sandbox_session.client('iam')

    policies = iam_client.list_policies()
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudigradePolicy",
                "Effect": "Allow",
                "Action": [
                    "sts:GetCallerIdentity",
                    "ec2:DescribeImages",
                    "ec2:DescribeInstances",
                    "ec2:ModifySnapshotAttribute",
                    "ec2:DescribeSnapshotAttribute",
                    "ec2:DescribeSnapshots",
                    "ec2:CopyImage",
                    "ec2:CreateTags",
                    "ec2:DescribeRegions",
                    "cloudtrail:CreateTrail",
                    "cloudtrail:UpdateTrail",
                    "cloudtrail:PutEventSelectors",
                    "cloudtrail:DescribeTrails",
                    "cloudtrail:StartLogging",
                    "cloudtrail:DeleteTrail"
                ],
                "Resource": "*"
            }
        ]
    }

    md5_policy = hashlib.md5(json.dumps(policy).encode()).hexdigest()

    if policy_name not in [policy['PolicyName'] for policy in policies['Policies']]:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy),
            Description="Policy to grant access to Red Hat Hybrid Cloud Console to the AWS account"
        )

        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            logger.error("Failed to create the policy")
            sys.exit(1)

        logger.info("Policy created", policy_name=policy_name, md5=md5_policy)
    else:
        # update permission
        response = iam_client.create_policy_version(
            PolicyArn=f"arn:aws:iam::{account_id}:policy/{policy_name}",
            PolicyDocument=json.dumps(policy),
            SetAsDefault=True
        )

        logger.info("Policy updated", policy_name=policy_name, md5=md5_policy)



    # Create the role redhat-HCC-role, using the external_id created earlier
    # Get the external_id from db or generate a new one
    external_id = sandbox_data.get('external_id', {}).get('S', '')

    if not external_id:
        # generate a random uuid
        #external_id = str(uuid.uuid4())
        # generate a random string
        external_id = ''.join(
            random.choice(string.ascii_uppercase + string.digits)
            for _ in range(16)
        )
        set_str(dynamodb, new_sandbox, 'external_id', external_id)
        logger.info(f"Generated external_id", hcc_external_id=external_id)
    else:   # Create, if it doesn't exist, an IAM policy redhat-HCC-policy
        logger.info(f"External ID already exists", hcc_external_id=external_id)

    role_name = 'redhat-HCC-role'

    roles = iam_client.list_roles()

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {
                    "AWS": f"arn:aws:iam::{os.environ['REDHAT_ACCOUNT']}:root"
                },
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": external_id
                    }
                }
            }
        ]
    }

    if role_name in [role['RoleName'] for role in roles['Roles']]:
        # update the role to ensure it has the right external_id
        response = iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(policy_document)
        )
        logger.info("Role updated", role_name=role_name, hcc_external_id=external_id)
    else:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(policy_document),
        )

        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            logger.error("Failed to create the role")
            sys.exit(1)

        logger.info("Role created", role_name=role_name)

    logger = logger.bind(hcc_external_id=external_id)
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    logger = logger.bind(role_arn=role_arn)

    # Attach the policy to the role

    response = iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=f"arn:aws:iam::{account_id}:policy/{policy_name}"
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        logger.error("Failed to attach the policy to the role")
        sys.exit(1)
    else:
        logger.info("Policy attached to the role", role_name=role_name, policy_name=policy_name)

    # use requests and create the POST request

    try:
        access_token = get_sso_access_token()
    except Exception as e:
        logger.error("Error getting the access token to console.redhat.com", error=e)

    s = requests.Session()
    #s.auth = (os.environ['RH_USERNAME'], os.environ['RH_PASSWORD'])
    s.headers.update({"Authorization": f"Bearer {access_token}"})
    baseurl = 'https://console.redhat.com/api/sources/v3.1'

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
            if response.status_code not in [200, 201, 202, 204]:
                logger.error(f"Failed to delete the source: {response.text}", status_code=response.status_code, sandbox=new_sandbox)
                os.exit(1)

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
                "app_creation_workflow": "manual_configuration",
            }
        ],
        "authentications": [
            {
                "resource_type": "application",
                "resource_name": "cloud-meter",
                "authtype": "cloud-meter-arn",
                "username": role_arn,
                "extra": {
                    "external_id": external_id
                }
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

    source_id = response.json().get('sources', [{}])[0].get('id', '')
    logger.info(f"Source create in HCC", source_id=source_id)


if validation:
    # First ensure the current reservation of the sandbox is 'untested'

    sandbox_data = get_sandbox(dynamodb, new_sandbox)

    if sandbox_data:
        reservation_current = sandbox_data.get('reservation', {}).get('S', '')
        if sandbox_data.get('stage', {}).get('S', '') == STAGE4_VALIDATED:

            if sandbox_data.get('available', {}).get('BOOL', '') == False:
                set_bool(dynamodb, new_sandbox, 'available', True)
                logger.info(f"Set {new_sandbox} as available")
            logger.info("Sandbox is already validated. Skipping validation.")

            if reservation_current != reservation:
                set_str(dynamodb, new_sandbox, 'reservation', reservation)

                logger.info("Reservation updated",
                            previous_reservation=reservation_current)

            exit(0)

        if reservation_current != 'untested':
            logger.error("Sandbox reservation is not 'untested'. something's off.", found=reservation_current)
            exit(1)

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
        UpdateExpression='SET #r = :val1, #s = :val2, #c = :val3, #a = :val4',
        ExpressionAttributeNames={
            '#r': 'reservation',
            '#s': 'stage',
            '#c': 'creation_status',
            '#a': 'available'
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
            },
            ':val4': {
                'BOOL': True,
            }
        }
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        logger.error("Failed to update the reservation")
        sys.exit(1)

    logger.info(f"Moved {new_sandbox} to {reservation}")
    logger.info(f"Total duration: {round(time.time() - START_TIME)} seconds")
