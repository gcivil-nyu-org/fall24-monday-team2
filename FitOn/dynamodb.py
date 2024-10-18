import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from django.conf import settings
import uuid
from datetime import datetime


# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')

users_table = dynamodb.Table('Users')
threads_table = dynamodb.Table('ForumThreads')
posts_table = dynamodb.Table('ForumPosts')

password_reset_table = dynamodb.Table('PasswordResetRequests')

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
        response = users_table.scan(
            FilterExpression="#n = :username",
            ExpressionAttributeNames={"#n": "username"},
            ExpressionAttributeValues={":username": username}
        )
        users = response.get('Items', [])
        if users:
            return users[0]
        return None
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

def get_user_by_email(email):
    try:
        response = users_table.scan(
            FilterExpression="#e = :email",
            ExpressionAttributeNames={"#e": "email"},
            ExpressionAttributeValues={":email": email}
        )
        users = response.get('Items', [])
        if users:
            return MockUser(users[0])
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
        hashed_password = make_password(new_password)
        response = users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET password = :val',
            ExpressionAttributeValues={':val': hashed_password},
            ReturnValues='UPDATED_NEW'
        )
        return response
    except Exception as e:
        print(f"Error updating user password: {e}")
    return None


def get_last_reset_request_time(user_id):
    try:
        response = password_reset_table.get_item(Key={'user_id': user_id})
        if 'Item' in response:
            return response['Item'].get('last_request_time', None)
        return None
    except Exception as e:
        print(f"Error fetching reset request for user_id '{user_id}': {e}")
        return None

def update_reset_request_time(user_id):
    try:
        response = password_reset_table.put_item(
            Item={
                'user_id': user_id,
                'last_request_time': timezone.now().isoformat()
            }
        )
        return response
    except Exception as e:
        print(f"Error updating reset request time for user_id '{user_id}': {e}")
    return None


def get_user(user_id):
    try:
        response = users_table.get_item(
            Key={
                'user_id': user_id
            }
        )
        return response.get('Item')
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None


def update_user(user_id, update_data):
    try:
        # Create a mapping for reserved keywords
        expression_attribute_names = {}
        expression_attribute_values = {}
        
        # Build the update expression components
        update_expression_parts = []
        
        for key, value in update_data.items():
            placeholder_name = f"#{key}"
            placeholder_value = f":{key}"
            expression_attribute_names[placeholder_name] = key  # For reserved keywords
            expression_attribute_values[placeholder_value] = value["Value"]
            update_expression_parts.append(f"{placeholder_name} = {placeholder_value}")

        # Join the update expression parts
        update_expression = ", ".join(update_expression_parts)

        response = users_table.update_item(
            Key={
                'user_id': user_id
            },
            UpdateExpression=f"SET {update_expression}",
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues='UPDATED_NEW'
        )
        return response
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None

# -------------------------------
# Forums Functions
# -------------------------------

def create_thread(title, user_id, content):
    thread_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    
    thread = {
        'ThreadID': thread_id,
        'Title': title,
        'UserID': user_id,
        'Content': content,
        'CreatedAt': created_at
    }
    print(thread)
    
    threads_table.put_item(Item=thread)
    return thread

def fetch_all_threads():
    response = threads_table.scan()
    return response.get('Items', [])

def fetch_thread(thread_id):
    response = threads_table.get_item(Key={'ThreadID': thread_id})
    return response.get('Item', None)

def create_post(thread_id, user_id, content):
    post_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    
    post = {
        'PostID': post_id,
        'ThreadID': thread_id,
        'UserID': user_id,
        'Content': content,
        'CreatedAt': created_at
    }
    print(post)
    
    posts_table.put_item(Item=post)
    return post

def fetch_posts_for_thread(thread_id):
    response = posts_table.scan(
        FilterExpression="#tid = :thread_id",
        ExpressionAttributeNames={"#tid": "ThreadID"},  # Handle 'ThreadID' as an attribute name
        ExpressionAttributeValues={":thread_id": thread_id}  # Corrected to pass the thread ID
    )
    return response.get('Items', [])