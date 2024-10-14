import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from django.contrib.auth.hashers import check_password

# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')

users_table = dynamodb.Table('Users')

def get_user_by_username(username):
    try:
        # Perform a scan operation to find the user by the 'name' field
        response = users_table.scan(
            FilterExpression="#n = :username",
            ExpressionAttributeNames={"#n": "username"},  # Handle reserved keyword 'name'
            ExpressionAttributeValues={":username": username}  # Corrected to pass the raw string value
        )
        print(response)
        # Check if we found any users
        users = response.get('Items', [])
        if users:
            return users[0]  # Return the first user (assuming username is unique)
        else:
            return None  # No user found
    except Exception as e:
        print(f"Error querying DynamoDB for username '{username}': {e}")
        return None

def create_user(user_id, username, email, name, date_of_birth, gender, password):
    try:
        print(f"Attempting to create user: {user_id}, {username}, {email}, {name}, {date_of_birth}, {gender}")
        users_table.put_item(
            Item={
                'user_id': user_id,  # Partition key
                'username': username,
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

def delete_user_by_username(username):
    try:
        # First, get the user by username
        response = users_table.scan(
            FilterExpression="#n = :username",
            ExpressionAttributeNames={"#n": "username"},
            ExpressionAttributeValues={":username": username}
        )
        
        users = response.get('Items', [])
        if not users:
            print(f"No user found with username: {username}")
            return False  # No user to delete
        
        # Assuming the 'user_id' is the partition key
        user_id = users[0]['user_id']  # Get the user's 'user_id'

        # Delete the user by user_id (or username if it's the primary key)
        delete_response = users_table.delete_item(
            Key={
                'user_id': user_id  # Replace with your partition key
            }
        )
        print(f"User '{username}' successfully deleted.")
        return True

    except Exception as e:
        print(f"Error deleting user with username '{username}': {e}")
        return False


