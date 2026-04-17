# This script is used to set up the Auth0 tenant with the necessary roles 
# and users for this project.
# Greggory Hickman, April 2026

from google.cloud import datastore, storage
import os
import requests
import json
import time

datastore_client = datastore.Client()

# Load Auth0 and Photo Bucket credentials from JSON
with open("docs/credentials.json", "r", encoding="utf-8") as file:
    creds = json.load(file)

DOMAIN = creds.get("DOMAIN")
CLIENT_ID = creds.get("CLIENT_ID")
CLIENT_SECRET = creds.get("CLIENT_SECRET")

if DOMAIN == "\u0000" or CLIENT_ID == "\u0000" or CLIENT_SECRET == "\u0000":
    raise RuntimeError("Error: Missing required credentials (DOMAIN, CLIENT_ID, CLIENT_SECRET). Please add them to docs/credentials.json.")


# Get an access token for the Auth0 Management API
def get_token():
    url = f"https://{DOMAIN}/oauth/token"
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "audience": f"https://{DOMAIN}/api/v2/",
        "grant_type": "client_credentials"
    }
    res = requests.post(url, json=payload)

    return res.json()["access_token"]

# Create a role in Auth0 using the token from get_token()
def create_role(token, name, description=""):
    url = f"https://{DOMAIN}/api/v2/roles"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "name": name,
        "description": description
    }
    res = requests.post(url, json=payload, headers=headers)
    return res.json()

# Create a user in Auth0 using the token from get_token()
def create_user(token, email, password):
    url = f"https://{DOMAIN}/api/v2/users"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "email": email,
        "password": password,
        "connection": "Username-Password-Authentication"
    }
    res = requests.post(url, json=payload, headers=headers)
    return res.json()

# Assign a role to a user in Auth0 using the token from get_token()
def assign_role(token, user_id, role_id):
    url = f"https://{DOMAIN}/api/v2/roles/{role_id}/users"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "users": [user_id]
    }
    res = requests.post(url, json=payload, headers=headers)
    while res.status_code != 200 and role_id and user_id:
        print(f"Assigning role {role_id} to user {user_id} failed, retrying in 5 seconds...")
        time.sleep(5)
        res = requests.post(url, json=payload, headers=headers)
    return res.json()

# Create an entry in Datastore to store a user's data
def create_datastore_entry(role, sub):
    key = datastore_client.key("users")
    entity = datastore.Entity(key=key)
    entity.update({
        "role": role,
        "sub": sub
    })
    datastore_client.put(entity)

# Main
if __name__ == '__main__':
    token = get_token()

    user_count = 0
    role_count = 0

    # Load users and roles from JSON file
    with open("docs/users_roles.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    role_map = {} # Map role names to IDs for later assignment

    # Create roles
    for role in data.get("roles", []):
        name = role.get("name")
        description = role.get("description", "")
        new_role = create_role(token, name, description)
        new_role_id = new_role.get("id")
        role_map[name] = new_role_id
        if new_role_id:
            role_count += 1

    # Create users
    for user in data.get("users", []):
        email = user.get("email")
        password = user.get("password", "Password123!")
        if not email:
            continue
        created_user = create_user(token, email, password)
        user_id = created_user.get("user_id")
        if user_id:
            user_count += 1

        # Assign a role to the user using role_map
        role_name = user.get("role")
        role_id = role_map[role_name] if role_name in role_map else None
        if role_id:
            assign_role(token, user_id, role_id)
            create_datastore_entry(role_name, user_id)

    print(f"Successfully created {user_count} users and {role_count} roles in the Auth0 tenant.")