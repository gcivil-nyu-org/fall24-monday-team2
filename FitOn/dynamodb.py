import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from django.contrib.auth.hashers import check_password, make_password
from django.core.files.storage import default_storage
from django.utils import timezone
from django.conf import settings
import uuid
from datetime import datetime


# Connect to DynamoDB
dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
s3_client = boto3.client("s3", region_name="us-west-2")

users_table = dynamodb.Table("Users")
threads_table = dynamodb.Table("ForumThreads")
posts_table = dynamodb.Table("ForumPosts")

password_reset_table = dynamodb.Table("PasswordResetRequests")

applications_table = dynamodb.Table("FitnessTrainerApplications")


class MockUser:
    def __init__(self, user_data):
        self.email = user_data.get("email")
        self.username = user_data.get("username")
        self.password = user_data.get("password")
        self.is_active = True
        self.last_login = None
        self.pk = user_data.get("user_id")

    def get_email_field_name(self):
        return "email"


def get_user_by_username(username):
    try:
        response = users_table.scan(
            FilterExpression="#n = :username",
            ExpressionAttributeNames={"#n": "username"},
            ExpressionAttributeValues={":username": username},
        )
        users = response.get("Items", [])
        if users:
            return users[0]
        return None
    except Exception as e:
        print(f"Error querying DynamoDB for username '{username}': {e}")
        return None


def create_user(user_id, username, email, name, date_of_birth, gender, password):
    try:
        print(
            f"Attempting to create user: {user_id}, {username}, {email}, {name}, {date_of_birth}, {gender}"
        )
        users_table.put_item(
            Item={
                "user_id": user_id,  # Partition key
                "username": username,
                "email": email,
                "name": name,
                "date_of_birth": str(date_of_birth),
                "gender": gender,
                "password": password,  # Hashed password
            }
        )

        # Test to check if inserted user was inserted
        response = users_table.get_item(Key={"user_id": user_id})
        if "Item" in response:
            print("User found in DynamoDB:", response["Item"])
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
            ExpressionAttributeValues={":username": username},
        )

        users = response.get("Items", [])
        if not users:
            print(f"No user found with username: {username}")
            return False  # No user to delete

        # Assuming the 'user_id' is the partition key
        user_id = users[0]["user_id"]  # Get the user's 'user_id'

        # Delete the user by user_id (or username if it's the primary key)
        delete_response = users_table.delete_item(
            Key={"user_id": user_id}  # Replace with your partition key
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
            ExpressionAttributeValues={":email": email},
        )
        users = response.get("Items", [])
        if users:
            return MockUser(users[0])
        return None
    except Exception as e:
        print(f"Error querying DynamoDB for email '{email}': {e}")
        return None


def get_user_by_uid(uid):
    try:
        response = users_table.get_item(Key={"user_id": uid})
        return response.get("Item", None)
    except Exception as e:
        print(f"Error fetching user by UID: {e}")
        return None


def update_user_password(user_id, new_password):
    try:
        hashed_password = make_password(new_password)
        response = users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET password = :val",
            ExpressionAttributeValues={":val": hashed_password},
            ReturnValues="UPDATED_NEW",
        )
        return response
    except Exception as e:
        print(f"Error updating user password: {e}")
    return None


def get_last_reset_request_time(user_id):
    try:
        response = password_reset_table.get_item(Key={"user_id": user_id})
        if "Item" in response:
            return response["Item"].get("last_request_time", None)
        return None
    except Exception as e:
        print(f"Error fetching reset request for user_id '{user_id}': {e}")
        return None


def update_reset_request_time(user_id):
    try:
        response = password_reset_table.put_item(
            Item={"user_id": user_id, "last_request_time": timezone.now().isoformat()}
        )
        return response
    except Exception as e:
        print(f"Error updating reset request time for user_id '{user_id}': {e}")
    return None


def get_user(user_id):
    try:
        response = users_table.get_item(Key={"user_id": user_id})
        return response.get("Item")
    except ClientError as e:
        print(e.response["Error"]["Message"])
        return None


def upload_profile_picture(user_id, profile_picture):
    try:
        # Create a custom filename based on user_id
        picture_name = f"{user_id}_profile.jpg"

        # Upload to S3
        s3_client.upload_fileobj(
            profile_picture,
            settings.AWS_STORAGE_BUCKET_NAME,
            f"static/images/{picture_name}",
            ExtraArgs={"ContentType": profile_picture.content_type},
        )

        # Construct the new image URL
        image_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/static/images/{picture_name}"
        return image_url

    except ClientError as e:
        print(e.response["Error"]["Message"])
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
            Key={"user_id": user_id},
            UpdateExpression=f"SET {update_expression}",
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW",
        )
        return response
    except ClientError as e:
        print(e.response["Error"]["Message"])
        return None


def add_fitness_trainer_application(
    user_id,
    past_experience_trainer,
    past_experience_dietician,
    resume,
    certifications,
    reference_name,
    reference_contact,
):
    try:
        # Define S3 paths
        resume_key = f"media/resumes/{user_id}_{resume.name}"
        certifications_key = None

        # Upload resume to S3
        s3_client.upload_fileobj(
            resume,
            settings.AWS_STORAGE_BUCKET_NAME,
            resume_key,
            ExtraArgs={"ContentType": resume.content_type},
        )

        # Check if certifications are provided and upload them
        if certifications:
            certifications_key = f"media/certifications/{user_id}_{certifications.name}"
            s3_client.upload_fileobj(
                certifications,
                settings.AWS_STORAGE_BUCKET_NAME,
                certifications_key,
                ExtraArgs={"ContentType": certifications.content_type},
            )

        # Insert data into the DynamoDB table
        response = applications_table.put_item(
            Item={
                "user_id": user_id,
                "past_experience_trainer": past_experience_trainer,
                "past_experience_dietician": past_experience_dietician,
                "resume": resume_key,  # Save S3 path to the uploaded resume
                "certifications": certifications_key,  # Save S3 path to the uploaded certification
                "reference_name": reference_name,
                "reference_contact": reference_contact,
            }
        )

        # Check response status
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            print("Fitness trainer application submitted successfully.")
            return True
        else:
            print(f"Failed to submit application: {response}")
            return False

    except (NoCredentialsError, PartialCredentialsError) as cred_err:
        print(f"Credentials error: {cred_err}")
        return False

    except ClientError as client_err:
        print(f"Client error: {client_err.response['Error']['Message']}")
        return False

    except Exception as e:
        print(f"Unexpected error submitting application: {e}")
        return False


def get_fitness_trainer_applications():
    try:
        # Scan DynamoDB table for all applications
        response = applications_table.scan()
        applications = response.get("Items", [])

        # Process the list of applications to generate S3 URLs
        for application in applications:
            # Generate S3 URLs for resume and certifications
            s3_client = boto3.client("s3")
            application["resume_url"] = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.AWS_STORAGE_BUCKET_NAME,
                    "Key": application["resume"],
                },
                ExpiresIn=3600,  # URL valid for 1 hour
            )

            # Check if certifications exist, and generate presigned URL
            if application.get("certifications"):
                application["certifications_url"] = s3_client.generate_presigned_url(
                    "get_object",
                    Params={
                        "Bucket": settings.AWS_STORAGE_BUCKET_NAME,
                        "Key": application["certifications"],
                    },
                    ExpiresIn=3600,
                )
            else:
                application["certifications_url"] = None

            user = get_user(application["user_id"])
            application["username"] = user["username"] if user else "Unknown"

        return applications

    except ClientError as client_err:
        print(f"Client error: {client_err.response['Error']['Message']}")
        return []
    except Exception as e:
        print(f"Unexpected error retrieving applications: {e}")
        return []


# -------------------------------
# Forums Functions
# -------------------------------


def create_thread(title, user_id, content):
    thread_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    thread = {
        "ThreadID": thread_id,
        "Title": title,
        "UserID": user_id,
        "Content": content,
        "CreatedAt": created_at,
        "Likes": 0,
        "LikedBy": [],
    }
    print(thread)

    threads_table.put_item(Item=thread)
    return thread


def fetch_all_threads():
    threads = threads_table.scan().get("Items", [])

    for thread in threads:
        # Convert the thread's 'CreatedAt' string to a datetime object
        thread_created_at_str = thread.get("CreatedAt")
        if thread_created_at_str:
            thread["CreatedAt"] = datetime.fromisoformat(thread_created_at_str)

        # Fetch all posts for this thread
        replies = fetch_posts_for_thread(thread["ThreadID"])

        # Add reply count
        thread["ReplyCount"] = len(replies)

        # Determine the latest post (if there are any replies)
        if replies:
            latest_post = max(replies, key=lambda x: x["CreatedAt"])

            # Convert 'CreatedAt' string to a Python datetime object for the latest post
            last_post_time_str = latest_post["CreatedAt"]
            last_post_time = datetime.fromisoformat(last_post_time_str)

            thread["LastPostUser"] = latest_post["UserID"]
            thread["LastPostTime"] = last_post_time
        else:
            thread["LastPostUser"] = "No replies yet"
            thread["LastPostTime"] = None

    return threads


def fetch_thread(thread_id):
    response = threads_table.get_item(Key={"ThreadID": thread_id})
    return response.get("Item", None)


def create_post(thread_id, user_id, content):
    post_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    post = {
        "PostID": post_id,
        "ThreadID": thread_id,
        "UserID": user_id,
        "Content": content,
        "CreatedAt": created_at,
    }
    print(post)

    posts_table.put_item(Item=post)
    return post


def fetch_posts_for_thread(thread_id):
    response = posts_table.scan(
        FilterExpression="#tid = :thread_id",
        ExpressionAttributeNames={
            "#tid": "ThreadID"
        },  # Handle 'ThreadID' as an attribute name
        ExpressionAttributeValues={
            ":thread_id": thread_id
        },  # Corrected to pass the thread ID
    )
    return response.get("Items", [])


def create_reply(thread_id, user_id, content):
    post_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    reply = {
        "ThreadID": thread_id,
        "PostID": post_id,
        "UserID": user_id,
        "Content": content,
        "CreatedAt": created_at,
    }

    # Insert the reply into the DynamoDB table
    posts_table.put_item(Item=reply)


def get_replies(thread_id):
    response = posts_table.scan(
        FilterExpression="#tid = :thread_id",
        ExpressionAttributeNames={
            "#tid": "ThreadID"
        },  # Handle 'ThreadID' as an attribute name
        ExpressionAttributeValues={":thread_id": thread_id},  # Pass the thread ID value
    )
    return response.get("Items", [])


def get_thread_details(thread_id):
    response = posts_table.scan(
        FilterExpression="#tid = :thread_id",
        ExpressionAttributeNames={"#tid": "ThreadID"},
        ExpressionAttributeValues={":thread_id": thread_id},
    )

    items = response.get("Items", [])
    if items:
        return items[0]  # Assuming the thread details are in the first item
    return None


def delete_post(post_id, thread_id):
    """
    Deletes a post from the DynamoDB posts table based on the post ID and thread ID.
    """
    try:
        response = posts_table.delete_item(
            Key={
                "ThreadID": thread_id,  # Adjust this according to your table schema
                "PostID": post_id,
            }
        )
        return True
    except Exception as e:
        print("Error deleting post: {e}")
        return False


def fetch_filtered_threads(
    username="", thread_type="all", start_date="", end_date="", search_text=""
):
    # Start building the filter expression
    filter_expression = Attr(
        "ThreadID"
    ).exists()  # A base filter that always evaluates to true (returns all)

    # Apply username filter if provided
    if username:
        filter_expression &= Attr("UserID").eq(username)

    # Apply date range filter if provided
    if start_date:
        start_date_dt = datetime.strptime(start_date, "%Y-%m-%d").isoformat()
        filter_expression &= Attr("CreatedAt").gte(start_date_dt)

    if end_date:
        end_date_dt = datetime.strptime(end_date, "%Y-%m-%d").isoformat()
        filter_expression &= Attr("CreatedAt").lte(end_date_dt)

    # Apply search text filter if provided (checks both thread titles and content)
    if search_text:
        filter_expression &= Attr("Title").contains(search_text) | Attr(
            "Content"
        ).contains(search_text)

    # Apply type filter (thread/reply) if provided
    if thread_type == "thread":
        filter_expression &= Attr("ReplyCount").eq(
            0
        )  # Assuming threads with 0 replies are initial posts
    elif thread_type == "reply":
        filter_expression &= Attr("ReplyCount").gt(0)  # Show threads with replies

    # Scan the DynamoDB table with the filter expression
    response = threads_table.scan(FilterExpression=filter_expression)

    threads = response.get("Items", [])

    # Process each thread (e.g., add reply count and last post info)
    for thread in threads:
        thread_created_at_str = thread.get("CreatedAt")
        if thread_created_at_str:
            thread["CreatedAt"] = datetime.fromisoformat(thread_created_at_str)

        replies = fetch_posts_for_thread(thread["ThreadID"])
        thread["ReplyCount"] = len(replies)

        if replies:
            latest_post = max(replies, key=lambda x: x["CreatedAt"])
            last_post_time_str = latest_post["CreatedAt"]
            thread["LastPostUser"] = latest_post["UserID"]
            thread["LastPostTime"] = datetime.fromisoformat(last_post_time_str)
        else:
            thread["LastPostUser"] = "No replies yet"
            thread["LastPostTime"] = None

    return threads


def fetch_all_users():
    # This will scan the threads table to get all unique users
    response = threads_table.scan(
        ProjectionExpression="UserID"  # Only fetch the UserID attribute
    )

    threads = response.get("Items", [])

    # Set to store unique user IDs
    unique_users = set()

    for thread in threads:
        user_id = thread.get("UserID")
        if user_id:
            unique_users.add(user_id)

    # Return the list of unique user IDs
    return [{"username": user} for user in unique_users]
