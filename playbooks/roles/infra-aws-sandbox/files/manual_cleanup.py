#!/usr/bin/env python3

import boto3

changed = False

# Cleanup Public ECR
client = boto3.client('ecr-public')

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


# Display Change
if changed:
    print("Changes were made")
