#!/usr/bin/env python3

import json
import os
import time
import boto3
import botocore

changed = False

aws_nuke_filter = {}

# if /tmp/aws_nuke_filters.json exists, load it
if os.path.exists('/tmp/aws_nuke_filters.json'):
    with open('/tmp/aws_nuke_filters.json', 'r') as f:
        aws_nuke_filter.update(json.load(f))

# Delete all Cognito User Pools

client = boto3.client('cognito-idp')

try:
    response = client.list_user_pools(
        MaxResults=60
    )

    for user_pool in response['UserPools']:
        # Delete all users
        response2 = client.list_users(
            UserPoolId=user_pool['Id']
        )

        for user in response2['Users']:
            client.admin_delete_user(
                UserPoolId=user_pool['Id'],
                Username=user['Username']
            )
            print("Deleted user: " + user['Username'])
            changed = True

        # Disable deletion protection
        client.update_user_pool(
            UserPoolId=user_pool['Id'],
            DeletionProtection='INACTIVE',
            AutoVerifiedAttributes=[
                'email'
            ]
        )
        # Delete user pool
        client.delete_user_pool(
            UserPoolId=user_pool['Id']
        )
        print("Deleted user pool: " + user_pool['Id'])
        changed = True

except botocore.exceptions.ClientError as e:
    print(e)

# Delete all app registry applications

client = boto3.client('servicecatalog-appregistry')

try:
    response = client.list_applications()

    for application in response['applications']:
        # Delete all resources
        response2 = client.list_associated_resources(
            application=application['id']
        )

        for resource in response2['resources']:
            client.disassociate_resource(
                application=application['id'],
                resource=resource['resourceType'],
                resourceType=resource['resourceType']
            )
            print("Disassociated resource: " + resource['resourceType'])
            changed = True

        # Delete application
        client.delete_application(
            application=application['id']
        )
        print("Deleted application: " + application['id'])
        changed = True


except botocore.exceptions.ClientError as e:
    print(e)

# Cleanup AWSBackupRecoveryPoint
client = boto3.client('backup')

try:
    # Get all vaults
    response = client.list_backup_vaults()

    for vault in response['BackupVaultList']:
        # Change access policy so we can delete recovery points later

        response2 = client.get_backup_vault_access_policy(
            BackupVaultName=vault['BackupVaultName']
        )

        if response2['Policy'] != '{}':
            # Set to empty policy
            client.put_backup_vault_access_policy(
                BackupVaultName=vault['BackupVaultName'],
                Policy='''{"Version": "2012-10-17", "Statement": [
                {
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
                "Resource": "*",
            "Action": ["backup:StartCopyJob"]}]}''')

        # Get all recovery points
        response2 = client.list_recovery_points_by_backup_vault(
            BackupVaultName=vault['BackupVaultName']
        )

        for recovery_point in response2['RecoveryPoints']:
            # Delete recovery point
            client.delete_recovery_point(
                BackupVaultName=vault['BackupVaultName'],
                RecoveryPointArn=recovery_point['RecoveryPointArn']
            )
            print(recovery_point['RecoveryPointArn'])
            print("Deleted recovery point: " + recovery_point['RecoveryPointArn'])
            changed = True

        # Delete vault
        # If vault is aws/efs/automatic-backup-vault ignore

        if vault['BackupVaultName'] == 'aws/efs/automatic-backup-vault':
            print("Skipping vault: " + vault['BackupVaultName'])
            continue

        client.delete_backup_vault(
            BackupVaultName=vault['BackupVaultName']
        )
        print("Deleted vault: " + vault['BackupVaultName'])
        changed = True

except botocore.exceptions.ClientError as e:
    print(e)


# Cleanup VPC Endpoints EC2VPCEndpointConnection
client = boto3.client('ec2')

try:
    response = client.describe_vpc_endpoint_connections()


    for connection in response['VpcEndpointConnections']:
        # Reject connection
        if connection['VpcEndpointState'] == "rejected":
            print("VPC Endpoint Connection is already rejected: " + connection['VpcEndpointId'])
            # ignore this connection
            aws_nuke_filter['EC2VPCEndpointConnection'] = aws_nuke_filter.get('EC2VPCEndpointConnection', [])
            aws_nuke_filter['EC2VPCEndpointConnection'].append(connection['ServiceId'])
            continue
        client.reject_vpc_endpoint_connections(
            ServiceId=connection['ServiceId'],
            VpcEndpointIds=[connection['VpcEndpointId']]
        )
        print("Rejected VPC Endpoint Connection: " + connection['VpcEndpointId'])
        changed = True

except client.exceptions.EndpointConnectionError:
    print("EC2VPCEndpointConnection is not supported in this region")
except botocore.exceptions.ClientError as e:
    print(e)

# Cleanup Public ECR
client = boto3.client('ecr-public')

if os.environ.get('AWS_REGION') == 'us-east-1':
    try:
        response = client.describe_repositories()

        for repo in response['repositories']:
            # Delete all images inside the repository
            # Get all images
            response2 = client.describe_images(repositoryName=repo['repositoryName'])

            # Delete all images
            for image in response2['imageDetails']:
                client.batch_delete_image(
                    repositoryName=repo['repositoryName'],
                    imageIds=[
                        {
                            'imageDigest': image['imageDigest']
                        }
                    ]
                )
                changed = True

                print("Deleted image: " + image['imageDigest'])

            # Delete repository

            client.delete_repository(
                repositoryName=repo['repositoryName']
            )
            print("Deleted repository: " + repo['repositoryName'])
            changed = True

    except botocore.exceptions.EndpointConnectionError:
        print("ECR Public is not supported in this region")

# Cleanup MGNSourceServer
client = boto3.client('mgn')

try:
    response = client.describe_source_servers()
    for server in response['items']:
        # Stop replication if it is running
        if server['dataReplicationInfo']['dataReplicationState'] != 'STOPPED':
            client.stop_replication(
                sourceServerID=server['sourceServerID']
            )
            print("Stopped replication for server: " + server['sourceServerID'])
            changed = True


        # Wait for replication to stop
        while True:
            response2 = client.describe_source_servers(
                filters={
                    'sourceServerIDs': [
                        server['sourceServerID']
                    ]
                }
            )
            if response2['items'][0]['dataReplicationInfo']['dataReplicationState'] == 'STOPPED':
                print()
                break
            print('.', end='')
            time.sleep(2)

        # Disconnect from service
        client.disconnect_from_service(
            sourceServerID=server['sourceServerID']
        )
        print("Disconnected from service: " + server['sourceServerID'])

        # Delete source server
        client.delete_source_server(
             sourceServerID=server['sourceServerID']
        )
        print("Deleted source server: " + server['sourceServerID'])
        changed = True
# UninitializedAccountException
except client.exceptions.UninitializedAccountException:
    print("MGNSourceServer is not supported in this region")




# Display Change
if changed:
    print("Changes were made")

# write to /tmp/aws_nuke_filters.json
with open('/tmp/aws_nuke_filters.json', 'w') as f:
    json.dump(aws_nuke_filter, f)
