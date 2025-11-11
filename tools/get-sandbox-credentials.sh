#!/usr/bin/env bash
set -euo pipefail

# Sandbox Credentials Retrieval Tool
# Usage: ./get-sandbox-credentials.sh [OPTIONS] [USER]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CREDENTIALS_DIR="${SCRIPT_DIR}/../credentials"
CREDENTIALS_DIR="${CREDENTIALS_DIR:-$DEFAULT_CREDENTIALS_DIR}"

usage() {
    cat << EOF
Sandbox Credentials Retrieval Tool

USAGE:
    $0 [OPTIONS] [USER]

OPTIONS:
    -h, --help              Show this help message
    -d, --dir DIR           Credentials directory (default: $DEFAULT_CREDENTIALS_DIR)
    -l, --list              List all available users
    -j, --json              Output JSON format instead of human-readable
    -t, --token USER        Get just the service account token for USER
    -p, --password USER     Get just the Keycloak password for USER (if available)
    -c, --login-cmd USER    Get oc login command for USER
    --all-json              Output all users' credentials as JSON array

EXAMPLES:
    # List all users
    $0 --list
    
    # Get credentials for specific user
    $0 john.doe
    $0 --json john.doe
    
    # Get just the token
    $0 --token john.doe
    
    # Get login command
    $0 --login-cmd john.doe
    
    # Get all users as JSON
    $0 --all-json

ENVIRONMENT VARIABLES:
    CREDENTIALS_DIR         Override default credentials directory

EOF
}

error() {
    echo "Error: $1" >&2
    exit 1
}

list_users() {
    if [[ ! -d "$CREDENTIALS_DIR" ]]; then
        error "Credentials directory not found: $CREDENTIALS_DIR"
    fi
    
    echo "Available sandbox users:"
    echo
    
    local count=0
    for file in "$CREDENTIALS_DIR"/*-credentials.txt; do
        [[ -f "$file" ]] || continue
        local user=$(basename "$file" | sed 's/-credentials\.txt$//')
        echo "  $user"
        ((count++))
    done
    
    if [[ $count -eq 0 ]]; then
        echo "  (no users found)"
    else
        echo
        echo "Total: $count users"
        echo
        echo "Credentials directory: $CREDENTIALS_DIR"
    fi
}

get_user_credentials() {
    local user="$1"
    local format="${2:-txt}"
    
    local file="$CREDENTIALS_DIR/${user}-credentials.${format}"
    
    if [[ ! -f "$file" ]]; then
        error "Credentials not found for user: $user (looking for: $file)"
    fi
    
    cat "$file"
}

get_token() {
    local user="$1"
    local json_file="$CREDENTIALS_DIR/${user}-credentials.json"
    
    if [[ ! -f "$json_file" ]]; then
        error "JSON credentials not found for user: $user"
    fi
    
    jq -r '.credentials[0].token' "$json_file"
}

get_password() {
    local user="$1"
    local json_file="$CREDENTIALS_DIR/${user}-credentials.json"
    
    if [[ ! -f "$json_file" ]]; then
        error "JSON credentials not found for user: $user"
    fi
    
    local password
    password=$(jq -r '.credentials[1].password // empty' "$json_file")
    
    if [[ -z "$password" ]]; then
        error "Keycloak password not available for user: $user (Keycloak not enabled?)"
    fi
    
    echo "$password"
}

get_login_cmd() {
    local user="$1"
    local json_file="$CREDENTIALS_DIR/${user}-credentials.json"
    
    if [[ ! -f "$json_file" ]]; then
        error "JSON credentials not found for user: $user"
    fi
    
    local api_url namespace token username password
    api_url=$(jq -r '.cluster.apiUrl' "$json_file")
    namespace=$(jq -r '.namespace' "$json_file")
    token=$(jq -r '.credentials[0].token' "$json_file")
    username=$(jq -r '.credentials[1].username // empty' "$json_file")
    password=$(jq -r '.credentials[1].password // empty' "$json_file")
    
    echo "# Login commands for user: $user"
    echo
    echo "# Using service account token:"
    echo "oc login '$api_url' --token='$token' --namespace='$namespace'"
    echo
    
    if [[ -n "$username" && -n "$password" ]]; then
        echo "# Using Keycloak credentials:"
        echo "oc login '$api_url' --username='$username' --password='$password'"
        echo
    fi
    
    echo "# Verify access:"
    echo "oc whoami"
    echo "oc get pods -n '$namespace'"
}

get_all_json() {
    if [[ ! -d "$CREDENTIALS_DIR" ]]; then
        error "Credentials directory not found: $CREDENTIALS_DIR"
    fi
    
    local users=()
    for file in "$CREDENTIALS_DIR"/*-credentials.json; do
        [[ -f "$file" ]] || continue
        users+=("$file")
    done
    
    if [[ ${#users[@]} -eq 0 ]]; then
        echo "[]"
        return
    fi
    
    # Use jq to create a proper JSON array
    jq -s '.' "${users[@]}"
}

# Main script logic
main() {
    # Check if credentials directory exists
    if [[ ! -d "$CREDENTIALS_DIR" ]]; then
        error "Credentials directory not found: $CREDENTIALS_DIR
        
Run the create-sandbox-users.yml playbook first to create users."
    fi
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -d|--dir)
                CREDENTIALS_DIR="$2"
                shift 2
                ;;
            -l|--list)
                list_users
                exit 0
                ;;
            -j|--json)
                if [[ $# -lt 2 ]]; then
                    error "Missing user argument for --json"
                fi
                get_user_credentials "$2" "json"
                exit 0
                ;;
            -t|--token)
                if [[ $# -lt 2 ]]; then
                    error "Missing user argument for --token"
                fi
                get_token "$2"
                exit 0
                ;;
            -p|--password)
                if [[ $# -lt 2 ]]; then
                    error "Missing user argument for --password"
                fi
                get_password "$2"
                exit 0
                ;;
            -c|--login-cmd)
                if [[ $# -lt 2 ]]; then
                    error "Missing user argument for --login-cmd"
                fi
                get_login_cmd "$2"
                exit 0
                ;;
            --all-json)
                get_all_json
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                ;;
            *)
                # Assume it's a username
                get_user_credentials "$1" "txt"
                exit 0
                ;;
        esac
    done
    
    # If no arguments, show usage
    echo "No action specified. Use --help for usage information."
    echo
    list_users
}

# Ensure jq is available for JSON operations
if ! command -v jq >/dev/null 2>&1; then
    error "jq is required but not installed. Please install jq to use this tool."
fi

main "$@"