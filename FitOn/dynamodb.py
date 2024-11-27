from boto3.dynamodb.conditions import Attr
import boto3
import uuid
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from django.contrib.auth.hashers import make_password
from datetime import datetime, timezone
from django.conf import settings
from django.utils import timezone
from pytz import timezone

# Connect to DynamoDB
dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
s3_client = boto3.client("s3", region_name="us-west-2")

users_table = dynamodb.Table("Users")
threads_table = dynamodb.Table("ForumThreads")
posts_table = dynamodb.Table("ForumPosts")
fitness_table = dynamodb.Table("UserFitnessData")

password_reset_table = dynamodb.Table("PasswordResetRequests")

applications_table = dynamodb.Table("FitnessTrainerApplications")
fitness_trainers_table = dynamodb.Table("FitnessTrainers")

tz = timezone("EST")


class MockUser:
    def __init__(self, user_data):
        if isinstance(user_data, dict):
            self.user_id = user_data.get("user_id", None)
            self.email = user_data.get("email", "")
            self.username = user_data.get("username", "")
            self.password = user_data.get("password", "")
            self.date_of_birth = user_data.get("date_of_birth", "")
            self.is_active = user_data.get("is_active", True)
            self.last_login = user_data.get("last_login", None)
            self.pk = self.user_id
        # else:
        #     self.user_id = None
        #     self.email = ""
        #     self.username = ""
        #     self.password = ""
        #     self.date_of_birth = ""
        #     self.is_active = True
        #     self.last_login = None
        #     self.pk = None

    def get_email_field_name(self):
        return "email"

    def get_username(self):
        return self.username

    def is_authenticated(self):
        return True


def get_user_by_username(username):
    # try:
    response = users_table.scan(
        FilterExpression="#n = :username",
        ExpressionAttributeNames={"#n": "username"},
        ExpressionAttributeValues={":username": username},
    )
    users = response.get("Items", [])
    if users:
        return users[0]
    return None
    # except Exception as e:
    #     print(f"Error querying DynamoDB for username '{username}': {e}")
    #     return None


def create_user(user_id, username, email, name, date_of_birth, gender, password):
    # try:
    users_table.put_item(
        Item={
            "user_id": user_id,  # Partition key
            "username": username,
            "email": email,
            "name": name,
            "date_of_birth": str(date_of_birth),
            "gender": gender,
            "password": password,  # Hashed password
            "is_admin": False,
            "is_fitness_trainer": False,
            "is_muted": False,
            "is_banned": False,
            "punishment_date": "",
        }
    )

    # Test to check if inserted user was inserted
    # response = users_table.get_item(Key={"user_id": user_id})
    # if "Item" in response:
    #     print("User found in DynamoDB:", response["Item"])
    # else:
    #     print("User not found in DynamoDB after insertion.")

    # print("User created successfully.")
    return True
    # except Exception as e:
    #     print(f"Error creating user in DynamoDB: {e}")
    #     return False


def delete_user_by_username(username):
    # try:
    # First, get the user by username
    response = users_table.scan(
        FilterExpression="#n = :username",
        ExpressionAttributeNames={"#n": "username"},
        ExpressionAttributeValues={":username": username},
    )

    users = response.get("Items", [])
    if not users:
        # print(f"No user found with username: {username}")
        return False  # No user to delete

    # Assuming the 'user_id' is the partition key
    user_id = users[0]["user_id"]  # Get the user's 'user_id'

    # Delete the user by user_id (or username if it's the primary key)
    users_table.delete_item(Key={"user_id": user_id})  # Replace with your partition key

    # print(f"User '{username}' successfully deleted.")
    return True

    # except Exception as e:
    #     print(f"Error deleting user with username '{username}': {e}")
    #     return False


def get_user_by_email(email):
    # try:
    response = users_table.scan(FilterExpression=Attr("email").eq(email))
    users = response.get("Items", [])
    if users:
        return MockUser(users[0])
    return None
    # except Exception as e:
    #     print(f"Error querying DynamoDB for email '{email}': {e}")
    #     return None


def get_user_by_uid(uid):
    # try:
    # Fetch from DynamoDB table
    response = users_table.get_item(Key={"user_id": uid})
    user_data = response.get("Item", None)

    if user_data:
        return user_data
    return None
    # except Exception as e:
    #     return e


def update_user_password(user_id, new_password):
    # try:
    hashed_password = make_password(new_password)
    response = users_table.update_item(
        Key={"user_id": user_id},
        UpdateExpression="SET password = :val",
        ExpressionAttributeValues={":val": hashed_password},
        ReturnValues="UPDATED_NEW",
    )
    return response
    # except Exception as e:
    #     print(f"Error updating user password: {e}")
    # return None


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
        if not user_id:
            print("User ID is None. Cannot update reset request time.")
            return None

        # Insert a new entry or update the existing reset request time
        password_reset_table.put_item(
            Item={"user_id": user_id, "last_request_time": timezone.now().isoformat()}
        )
        print(f"Reset request time updated for user_id '{user_id}'.")
    except Exception as e:
        print(f"Error updating reset request time for user_id '{user_id}': {e}")


def get_user(user_id):
    try:
        response = users_table.get_item(Key={"user_id": user_id})
        return response.get("Item")
    except ClientError as e:
        print(e.response["Error"]["Message"])
        return None


def upload_profile_picture(user_id, profile_picture):
    # try:
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

    # except ClientError as e:
    #     print(e.response["Error"]["Message"])
    #     return None


def update_user(user_id, update_data):
    # try:
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


# except ClientError as e:
#     print(e.response["Error"]["Message"])
#     return None


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


def get_fitness_trainers():
    try:
        # Scan DynamoDB table for all fitness trainers
        response = fitness_trainers_table.scan()
        trainers = response.get("Items", [])

        # Process the list of fitness trainers to generate S3 URLs
        for trainer in trainers:
            trainer["resume_url"] = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.AWS_STORAGE_BUCKET_NAME,
                    "Key": trainer["resume"],
                },
                ExpiresIn=3600,  # URL valid for 1 hour
            )

            # Check if certifications exist, and generate presigned URL
            if trainer.get("certifications"):
                trainer["certifications_url"] = s3_client.generate_presigned_url(
                    "get_object",
                    Params={
                        "Bucket": settings.AWS_STORAGE_BUCKET_NAME,
                        "Key": trainer["certifications"],
                    },
                    ExpiresIn=3600,
                )
            else:
                trainer["certifications_url"] = None

            user = get_user(trainer["user_id"])
            trainer["username"] = user["username"] if user else "Unknown"

        return trainers

    except ClientError as client_err:
        print(f"Client error: {client_err.response['Error']['Message']}")
        return []
    except Exception as e:
        print(f"Unexpected error retrieving fitness trainers: {e}")
        return []


def make_fitness_trainer(user_id):
    try:
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET is_fitness_trainer = :ft",
            ExpressionAttributeValues={":ft": True},
        )

        response = applications_table.get_item(Key={"user_id": user_id})
        application_item = response["Item"]

        fitness_trainers_table.put_item(Item=application_item)
        applications_table.delete_item(Key={"user_id": user_id})
    except Exception as e:
        print(f"Unexpected error making updates: {e}")
        return []


def remove_fitness_trainer(user_id):
    try:
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET is_fitness_trainer = :ft, is_rejected = :r",
            ExpressionAttributeValues={":ft": False, ":r": True},
        )
        fitness_trainers_table.delete_item(Key={"user_id": user_id})
        applications_table.delete_item(Key={"user_id": user_id})
    except Exception as e:
        print(f"Unexpected error making updates: {e}")
        return []


# -------------------------------
# Forums Functions
# -------------------------------


def create_thread(title, user_id, content, section="General"):
    thread_id = str(uuid.uuid4())

    created_at = datetime.now(tz).isoformat()

    thread = {
        "ThreadID": thread_id,
        "Title": title,
        "UserID": user_id,
        "Content": content,
        "Section": section,
        "CreatedAt": created_at,
        "Likes": 0,
        "LikedBy": [],
    }

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

    created_at = datetime.now(tz).isoformat()

    post = {
        "PostID": post_id,
        "ThreadID": thread_id,
        "UserID": user_id,
        "Content": content,
        "CreatedAt": created_at,
    }

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


def post_comment(thread_id, user_id, content):
    post_id = str(uuid.uuid4())
    created_at = datetime.now(tz).isoformat()

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
        posts_table.delete_item(
            Key={
                "ThreadID": thread_id,  # Adjust this according to your table schema
                "PostID": post_id,
            }
        )
        return True
    except Exception as e:
        print(f"Error deleting post: {e}")
        return False


def fetch_filtered_threads(
    section=None,
    username="",
    thread_type="all",
    start_date="",
    end_date="",
    search_text="",
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

    if section:
        filter_expression &= Attr("Section").eq(section)

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


############################
# Fetchng Fitness Data     #
############################


def get_fitness_data(metric, email, start_time, end_time):
    try:
        print("Inside Fitness Data Function\n")
        print("Start Time: \n", start_time)
        print("End Time: \n", end_time)
        response = fitness_table.scan(
            FilterExpression="metric = :m AND #t BETWEEN :start AND :end AND email = :email",
            ExpressionAttributeNames={"#t": "time"},
            ExpressionAttributeValues={
                ":m": metric,
                ":email": email,
                ":start": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                ":end": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
        print(
            f"Metric : {metric}\nResponse: {response}\n",
        )
        return response
    except Exception as e:
        print(f"Error querying DynamoDB for fitness data. {e}")


def delete_threads_by_user(user_id):
    """
    Deletes all threads in the specified DynamoDB table for a given user ID.

    Parameters:
    - user_id (str): The UserID for which threads should be deleted.
    """
    while True:
        # Scan the table for items where UserID matches the specified user_id
        response = threads_table.scan(
            FilterExpression="UserID = :user",
            ExpressionAttributeValues={":user": user_id},
            ProjectionExpression="ThreadID",
        )

        # Extract ThreadIDs from the scan result
        thread_ids = [item["ThreadID"] for item in response.get("Items", [])]

        # If there are no more items to delete, exit the loop
        if not thread_ids:
            break

        # Loop through each ThreadID and delete the item
        for thread_id in thread_ids:
            threads_table.delete_item(Key={"ThreadID": thread_id})


def delete_thread_by_id(thread_id):
    # Initialize the response to scan for posts associated with the thread
    response = posts_table.scan(FilterExpression=Attr("ThreadID").eq(thread_id))

    # Iterate through each item and delete it
    for item in response["Items"]:
        # Include both the partition key ('PostID') and the sort key ('ThreadID')
        posts_table.delete_item(
            Key={
                "PostID": item["PostID"],  # Your partition key
                "ThreadID": item["ThreadID"],  # Your sort key
            }
        )

    # Delete the thread from the threads table
    threads_table.delete_item(
        Key={
            "ThreadID": thread_id
        }  # Ensure this matches your table's primary key schema
    )

    return True


def get_thread(title, user_id, content, created_at):
    # try:
    response = threads_table.scan(
        FilterExpression="#title = :title AND #user = :user_id AND #content = :content AND #created = :created_at",
        ExpressionAttributeNames={
            "#title": "Title",
            "#user": "UserID",
            "#content": "Content",
            "#created": "CreatedAt",
        },
        ExpressionAttributeValues={
            ":title": title,
            ":user_id": user_id,
            ":content": content,
            ":created_at": created_at,
        },
    )

    threads = response.get("Items", [])
    if threads:
        return threads[0]
    else:
        return None

    # except Exception as e:
    #     print(f"Error retrieving thread: {e}")
    #     return None


# Zejun's Code


def create_reply(thread_id, user_id, content):
    reply_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    reply = {
        "ReplyID": reply_id,
        "UserID": user_id,
        "Content": content,
        "CreatedAt": created_at,
    }

    # Append the reply to the post's Replies attribute
    try:
        # Update the post by appending the new reply to the Replies list
        # UPDATE THIS LATER
        post_id = 1
        posts_table.update_item(
            Key={"PostID": post_id},
            UpdateExpression="SET Replies = list_append(if_not_exists(Replies, :empty_list), :reply)",
            ExpressionAttributeValues={
                ":reply": [reply],  # Append the reply as a list item
                ":empty_list": [],  # Default to an empty list if Replies doesn't exist
            },
        )
        return {"status": "success", "reply_id": reply_id}
    except Exception as e:
        print(f"Error adding reply: {e}")
        return {"status": "error", "message": str(e)}


def like_comment(post_id, user_id):
    # Fetch the comment by post_id
    response = posts_table.get_item(Key={"PostID": post_id})
    post = response.get("Item")

    if not post:
        raise ValueError("Comment not found")

    liked_by = post.get("LikedBy", [])
    likes = post.get("Likes", 0)

    # Check if the user has already liked the post
    if user_id in liked_by:
        # Unlike the post
        likes = max(0, likes - 1)
        liked_by.remove(user_id)
        liked = False
    else:
        # Like the post
        likes += 1
        liked_by.append(user_id)
        liked = True

    # Update the item in DynamoDB
    posts_table.update_item(
        Key={"PostID": post_id},
        UpdateExpression="SET Likes = :likes, LikedBy = :liked_by",
        ExpressionAttributeValues={":likes": likes, ":liked_by": liked_by},
    )

    return likes, liked


def report_comment(post_id, user_id):
    # Update the comment as reported by adding user_id to ReportedBy
    response = posts_table.get_item(Key={"PostID": post_id})
    post = response.get("Item")

    if not post:
        raise ValueError("Comment not found")

    reported_by = post.get("ReportedBy", [])
    if user_id not in reported_by:
        reported_by.append(user_id)

    # Update the item in DynamoDB
    posts_table.update_item(
        Key={"PostID": post_id},
        UpdateExpression="SET ReportedBy = :reported_by",
        ExpressionAttributeValues={":reported_by": reported_by},
    )


def delete_reply(post_id, thread_id, reply_id):
    try:
        # Fetch the post to get the current list of replies
        response = posts_table.get_item(Key={"PostID": post_id, "ThreadID": thread_id})
        post = response.get("Item")

        if not post or "Replies" not in post:
            return {"status": "error", "message": "Post or replies not found"}

        # Filter out the reply with the specific reply_id
        updated_replies = [
            reply for reply in post["Replies"] if reply["ReplyID"] != reply_id
        ]

        # Update the post in DynamoDB with the new list of replies
        posts_table.update_item(
            Key={"PostID": post_id, "ThreadID": thread_id},
            UpdateExpression="SET Replies = :updated_replies",
            ExpressionAttributeValues={":updated_replies": updated_replies},
        )

        return {"status": "success"}
    except Exception as e:
        print(f"Error deleting reply: {e}")
        return {"status": "error", "message": str(e)}


def fetch_reported_threads_and_comments():
    reported_threads = []
    reported_comments = []

    # Fetch reported threads
    try:
        response = threads_table.scan(FilterExpression=Attr("ReportedBy").exists())
        reported_threads = response.get("Items", [])
        print(f"Fetched {len(reported_threads)} reported threads.")
    except ClientError as e:
        print(f"Error fetching reported threads: {e.response['Error']['Message']}")

    # Fetch reported comments
    try:
        response = posts_table.scan(FilterExpression=Attr("ReportedBy").exists())
        reported_comments = response.get("Items", [])
        print(f"Fetched {len(reported_comments)} reported comments.")
    except ClientError as e:
        print(f"Error fetching reported comments: {e.response['Error']['Message']}")

    return {
        "reported_threads": reported_threads,
        "reported_comments": reported_comments,
    }


def mark_thread_as_reported(thread_id):
    try:
        # Fetch the thread to check if it already has "ReportedBy" attribute
        response = threads_table.get_item(Key={"ThreadID": thread_id})
        thread = response.get("Item", {})

        reported_by = thread.get("ReportedBy", [])

        # Mark the thread as reported (or add to the list if already exists)
        reported_by.append(
            "admin"
        )  # Replace "admin" with the reporting user ID if needed

        # Update the thread with the reported status
        threads_table.update_item(
            Key={"ThreadID": thread_id},
            UpdateExpression="SET ReportedBy = :reported_by",
            ExpressionAttributeValues={":reported_by": reported_by},
        )
        print(f"Thread {thread_id} reported.")
    except Exception as e:
        print(f"Error reporting thread {thread_id}: {e}")


def mark_comment_as_reported(thread_id, post_id, reporting_user):
    try:
        print(f"Fetching comment {post_id} in thread {thread_id}")
        response = posts_table.get_item(Key={"ThreadID": thread_id, "PostID": post_id})
        comment = response.get("Item", {})
        print(f"Comment fetched: {comment}")

        if not comment:
            print(f"Comment {post_id} not found in thread {thread_id}")
            return

        # Initialize ReportedBy if it doesn't exist
        reported_by = comment.get("ReportedBy", [])
        print(f"Current ReportedBy list: {reported_by}")

        # Avoid duplicate reporting
        if reporting_user not in reported_by:
            reported_by.append(reporting_user)

        # Update the comment with the ReportedBy field
        posts_table.update_item(
            Key={"ThreadID": thread_id, "PostID": post_id},
            UpdateExpression="SET ReportedBy = :reported_by",
            ExpressionAttributeValues={":reported_by": reported_by},
        )
        print(f"Successfully reported comment {post_id} in thread {thread_id}")
    except Exception as e:
        print(f"Error reporting comment: {e}")
