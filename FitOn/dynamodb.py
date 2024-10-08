import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')

# Reference to the Users table (replace 'Users' with your actual table name)
users_table = dynamodb.Table('Users')

def create_user(user_id, email, name):
    try:
        users_table.put_item(
            Item={
                'user_id': user_id,
                'email': email,
                'name': name,
            }
        )
        return True
    except (NoCredentialsError, PartialCredentialsError):
        print("Credentials not available or incomplete.")
        return False
