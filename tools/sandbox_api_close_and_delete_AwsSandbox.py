#!/usr/bin/env python3

import os
import sys
import requests
import json
import logging
from pathlib import Path

def main():
    # route comes from environment variable 'route'
    route = os.getenv('route')
    if route is None:
        print("route environment variable not set")
        sys.exit(1)

    # admintoken comes from environment variable 'admintoken'
    admintoken = os.getenv('admintoken')
    if admintoken is None:
        print("admintoken environment variable not set")
        sys.exit(1)

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <sandbox>")
        sys.exit(1)

    sandbox = sys.argv[1]

    # Detect if it's a tty
    if sys.stdin.isatty():
        answer = input(f"Are you sure you want to permanently delete the sandbox {sandbox}? [y/N] ")
    else:
        answer = 'y'
    if answer.lower() != 'y':
        print("Aborted.")
        sys.exit(1)

    logs_dir = Path.home() / 'logs'
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / 'sandbox_close_and_delete.log'
    logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    # First HTTP request to get access_token
    login_url = f"{route}/api/v1/login"
    headers = {
        'Authorization': f'Bearer {admintoken}',
    }

    response = requests.get(login_url, headers=headers)
    with open(log_file, 'a') as f:
        logging.info(f"GET {login_url}")
        logging.info(f"Response status: {response.status_code}")

    if response.status_code != 200:
        print(f"Failed to get access token. Status code: {response.status_code}")
        print(response.text)
        sys.exit(1)

    response_json = response.json()
    access_token = response_json.get('access_token')
    if not access_token:
        print("access_token not found in response")
        sys.exit(1)

    # Second HTTP request to delete the sandbox
    account_type = 'AwsSandbox'
    delete_url = f"{route}/api/v1/accounts/{account_type}/{sandbox}"
    headers = {
        'Authorization': f'Bearer {access_token}',
    }

    response = requests.delete(delete_url, headers=headers)
    with open(log_file, 'a') as f:
        logging.info(f"DELETE {delete_url}")
        logging.info(f"Response status: {response.status_code}")
        logging.info(f"Response body: {response.text}\n")

    if response.status_code not in [200, 204]:
        print(f"Failed to delete sandbox. Status code: {response.status_code}")
        print(response.text)
        sys.exit(1)
    else:
        print("Sandbox deleted successfully.")
        print(response.text)

if __name__ == "__main__":
    main()
