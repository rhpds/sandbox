#!/usr/bin/env python3

import sys
import time
import boto3
import botocore

changed = False

# Cleanup Public ECR
client = boto3.client('ecr-public')

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
except botocore.exceptions.EndpointConnectionError:
    print("MGNSourceServer is not supported in this region")


# Display Change
if changed:
    print("Changes were made")
