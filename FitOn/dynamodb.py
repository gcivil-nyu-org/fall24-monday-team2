import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')

# Reference to the Users table (replace 'Users' with your actual table name)
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
        if user and user['password'] == password:  # In production, use hashed passwords
            return True
        else:
            return False
    except Exception as e:
        print(f"Error checking user credentials: {e}")
        return False

def create_user(user_id, email, name, date_of_birth, gender, password):
    try:
        users_table.put_item(
            Item={
                'user_id': user_id,
                'email': email,
                'name': name,
                'date_of_birth': str(date_of_birth),
                'gender': gender,
                'password': password,  # Consider hashing the password for security
            }
        )
        return True
    except (NoCredentialsError, PartialCredentialsError):
        print("Credentials not available or incomplete.")
        return False

