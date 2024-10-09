import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from django.contrib.auth.hashers import check_password

# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')

users_table = dynamodb.Table('Users')

def check_user_credentials(username, password):
    try:
        # Query the DynamoDB Users table to find the user with the given username
        response = users_table.get_item(
            Key={
                'user_id': username
            }
        )
        # Check if the user exists and the password matches
        user = response.get('Item')
        if user and check_password(password, user['password']):  # In production, use hashed passwords
            return True
        else:
            return False
    except Exception as e:
        print(f"Error checking user credentials: {e}")
        return False

def create_user(user_id, email, name, date_of_birth, gender, password):
    try:
        print(f"Attempting to create user: {user_id}, {email}, {name}, {date_of_birth}, {gender}")
        users_table.put_item(
            Item={
                'user_id': user_id,  # Partition key
                'email': email,
                'name': name,
                'date_of_birth': str(date_of_birth),
                'gender': gender,
                'password': password,  # Hashed password
            }
        )
        
        # Test to check if inserted user was inserted
        response = users_table.get_item(
            Key={
                'user_id': user_id
            }
        )
        if 'Item' in response:
            print("User found in DynamoDB:", response['Item'])
        else:
            print("User not found in DynamoDB after insertion.")

        print("User created successfully.")
        return True
    except Exception as e:
        print(f"Error creating user in DynamoDB: {e}")
        return False



