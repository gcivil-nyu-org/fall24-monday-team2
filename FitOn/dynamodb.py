import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from boto3.dynamodb.conditions import Key
from django.contrib.auth.hashers import check_password, make_password


# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')

users_table = dynamodb.Table('Users')

class MockUser:
    def __init__(self, user_data):
        self.email = user_data.get('email')
        self.username = user_data.get('username')
        self.password = user_data.get('password')
        self.is_active = True
        self.last_login = None  
        self.pk = user_data.get('user_id')  
    
    def get_email_field_name(self):
        return "email"

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


def get_user_by_email(email):
    try:
        response = users_table.scan(
            FilterExpression="#e = :email",
            ExpressionAttributeNames={"#e": "email"},
            ExpressionAttributeValues={":email": email}
        )
        users = response.get('Items', [])
        if users:
            return MockUser(users[0])  # Wrap the DynamoDB response in MockUser
        return None
    except Exception as e:
        print(f"Error querying DynamoDB for email '{email}': {e}")
        return None
    

def get_user_by_uid(uid):
    try:
        response = users_table.get_item(Key={'user_id': uid})
        return response.get('Item', None)
    except Exception as e:
        print(f"Error fetching user by UID: {e}")
        return None
    

def update_user_password(user_id, new_password):
    try:
        hashed_password = make_password(new_password)  # Hash the password
        response = users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET password = :val',
            ExpressionAttributeValues={':val': hashed_password},  # Store the hashed password
            ReturnValues='UPDATED_NEW'
        )
        return response
    except Exception as e:
        print(f"Error updating user password: {e}")
    return None