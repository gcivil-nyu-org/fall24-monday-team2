from datetime import datetime
from django.test import TestCase, Client, override_settings, RequestFactory

from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch, MagicMock
from google.oauth2.credentials import Credentials

from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.urls import reverse
import boto3
import json
from FitOn.rds import (
    convert_to_mysql_datetime,
)  # Adjust the import path based on your project structure
from unittest import IsolatedAsyncioTestCase
from FitOn.rds import (
    get_secret_rds,
    create_connection,
    create_steps_table,
    create_glucose_table,
    create_heartRate_table,
    create_oxygen_table,
    create_pressure_table,
    create_restingHeartRate_table,
)
import aiomysql
from FitOn.rds import create_table, insert_data
from unittest import IsolatedAsyncioTestCase

# import unittest

# from django.contrib.auth.models import User
# from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password

# from django.contrib.auth.hashers import check_password

# from django.contrib.sessions.models import Session
# from django.utils import timezone
# from django.utils.http import urlsafe_base64_encode
# from django.utils.encoding import force_bytes
# from django.core import mail

# from django.utils import timezone

# import time
from .views import SCOPES

from .dynamodb import (
    create_user,
    delete_user_by_username,
    get_user_by_email,
    get_user_by_uid,
    get_user,
    update_user_password,
    update_user,
    create_thread,
    delete_threads_by_user,
    get_thread,
    delete_thread_by_id,
    fetch_all_threads,
    fetch_thread,
    create_post,
    fetch_filtered_threads,
    fetch_all_users,
    get_thread_details,
    delete_post,
    get_section_stats,
    # MockUser,
    # users_table,
)
from botocore.exceptions import ClientError, ValidationError
import pytz
from django.contrib import messages
from django.contrib.messages import get_messages
from .forms import (
    SignUpForm,
    SetNewPasswordForm,
    ProfileForm,
    validate_file_extension,
)
from .views import (
    SCOPES,
    homepage,
    add_message,
    perform_redirect,
    login,
    custom_logout,
    signup,
    forum_view,
)
from django.contrib.auth.hashers import check_password, make_password


class UserCreationAndDeletionTests(TestCase):
    def setUp(self):
        # Initialize DynamoDB resource and Users table
        self.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
        self.users_table = self.dynamodb.Table("Users")

        # Define user data for the test
        self.user_data = {
            "user_id": "test_user_123",
            "username": "test_user123",
            "email": "test_user@example.com",
            "name": "Test User",
            "date_of_birth": "1990-01-01",
            "gender": "O",
            "height": "183",
            "weight": "83",
            "password": "hashed_password",
        }

    def test_create_user(self):
        # Step 1: Create the user
        result = create_user(**self.user_data)
        self.assertTrue(result, "User creation failed.")

        # Verify that the user was added by retrieving it from DynamoDB
        response = self.users_table.get_item(Key={"user_id": self.user_data["user_id"]})
        self.assertIn(
            "Item", response, "User was not found in DynamoDB after creation."
        )
        user = response["Item"]
        self.assertEqual(user["username"], self.user_data["username"])

    def test_get_user_by_email(self):
        # Ensure the user exists before testing retrieval
        create_user(**self.user_data)

        # Test get_user_by_email
        user_by_email = get_user_by_email(self.user_data["email"])
        self.assertIsNotNone(user_by_email, "get_user_by_email did not find the user.")
        self.assertEqual(
            user_by_email.email, self.user_data["email"], "Emails do not match."
        )
        self.assertEqual(
            user_by_email.username,
            self.user_data["username"],
            "Usernames do not match.",
        )

    def test_get_user_by_uid(self):
        # Ensure the user exists before testing retrieval
        create_user(**self.user_data)

        # Test get_user_by_uid
        user_by_uid = get_user_by_uid(self.user_data["user_id"])
        uid = user_by_uid.get("user_id")
        self.assertIsNotNone(user_by_uid, "get_user_by_uid did not find the user.")
        self.assertEqual(uid, self.user_data["user_id"], "User IDs do not match.")
        username = user_by_uid.get("username")
        self.assertEqual(username, self.user_data["username"])

    def test_get_user(self):
        # Step 1: Ensure the user exists by calling create_user
        create_result = create_user(**self.user_data)
        self.assertTrue(create_result, "User creation failed.")

        # Step 2: Call get_user to retrieve the user by user_id
        retrieved_user = get_user(self.user_data["user_id"])

        # Step 3: Verify the retrieved user matches the expected data
        self.assertIsNotNone(retrieved_user, "get_user did not find the user.")
        self.assertEqual(
            retrieved_user["user_id"],
            self.user_data["user_id"],
            "User IDs do not match.",
        )
        self.assertEqual(
            retrieved_user["username"],
            self.user_data["username"],
            "Usernames do not match.",
        )
        self.assertEqual(
            retrieved_user["email"], self.user_data["email"], "Emails do not match."
        )

    def test_update_user_password(self):
        # Step 1: Update the user's password
        new_password = "new_secure_password"
        update_result = update_user_password(self.user_data["user_id"], new_password)
        self.assertIsNotNone(update_result, "Password update failed.")

        # Step 2: Retrieve the user to verify the password update
        updated_user = get_user(self.user_data["user_id"])
        self.assertIsNotNone(updated_user, "User not found after password update.")

        # Step 3: Verify the password was updated correctly
        is_password_correct = check_password(new_password, updated_user["password"])
        self.assertTrue(is_password_correct, "The password was not updated correctly.")

    def test_update_user(self):
        # Step 1: Define the updates
        update_data = {
            "email": {"Value": "updated_user@example.com"},
            "name": {"Value": "Updated-Test User"},
            "gender": {"Value": "F"},
        }

        # Step 2: Call update_user
        update_result = update_user(self.user_data["user_id"], update_data)
        self.assertIsNotNone(update_result, "User update failed.")

        # Step 3: Retrieve the user to verify updates
        updated_user = get_user(self.user_data["user_id"])
        self.assertIsNotNone(updated_user, "User not found after update.")

        # Step 4: Check that the updated fields match the expected values
        self.assertEqual(
            updated_user["email"], update_data["email"]["Value"], "Email update failed."
        )
        self.assertEqual(
            updated_user["name"], update_data["name"]["Value"], "Name update failed."
        )
        self.assertEqual(
            updated_user["gender"],
            update_data["gender"]["Value"],
            "Gender update failed.",
        )

    def test_toggle_ban_user(self):
        # Step 1: Create the user
        create_user(**self.user_data)

        # Retrieve the user from DynamoDB to ensure the user is created
        user = get_user_by_uid("test_user_123")
        username = user.get("username")

        # Step 2: Ban the user by toggling `is_banned`
        response = self.client.post(
            "/ban_user/",
            data=json.dumps({"user_id": username}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        # Step 3: Manually retrieve the user from DynamoDB to verify `is_banned` is True
        response = self.users_table.get_item(Key={"user_id": self.user_data["user_id"]})
        self.assertIn("Item", response, "User was not found in DynamoDB after banning.")
        updated_user = response["Item"]

        # Check if `is_banned` is set to True
        self.assertTrue(
            updated_user.get("is_banned") is True,  # Updated assertion
            "User should be banned (is_banned should be True).",
        )

        # Step 4: Check that `punishment_date` is set
        self.assertIn(
            "punishment_date",
            updated_user,
            "punishment_date should be set when user is banned.",
        )

    def test_unban_user(self):
        # Ban the user first by directly setting is_banned to True and setting punishment_date
        self.users_table.update_item(
            Key={"user_id": self.user_data["user_id"]},
            UpdateExpression="set is_banned = :b, punishment_date = :d",
            ExpressionAttributeValues={
                ":b": True,
                ":d": datetime.now(pytz.timezone("US/Eastern")).isoformat(),
            },
        )

        create_user(**self.user_data)

        # Step 1: Unban the user
        response = self.client.post(
            "/unban_user/",
            data=json.dumps({"user_id": self.user_data["user_id"]}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data["message"],
            "User has been unbanned",
            "Unban message should confirm unban success.",
        )

        # Step 2: Verify the user is unbanned and punishment_date is removed
        unbanned_user = get_user(self.user_data["user_id"])
        self.assertFalse(
            unbanned_user.get("is_banned"),
            "User's is_banned should be False after unban.",
        )
        self.assertFalse(
            hasattr(unbanned_user, "punishment_date"),
            "punishment_date should be removed when user is unbanned.",
        )

    def test_toggle_mute_user(self):
        # Step 1: Create the user
        create_user(**self.user_data)

        # Retrieve the user from DynamoDB to ensure the user is created
        user = get_user_by_uid("test_user_123")
        username = user.get("username")

        # Step 2: Ban the user by toggling `is_muted`
        response = self.client.post(
            "/mute_user/",
            data=json.dumps({"user_id": username}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        # Step 3: Manually retrieve the user from DynamoDB to verify `is_muted` is True
        response = self.users_table.get_item(Key={"user_id": self.user_data["user_id"]})
        self.assertIn("Item", response, "User was not found in DynamoDB after muting.")
        updated_user = response["Item"]

        # Check if `is_muted` is set to True
        self.assertTrue(
            updated_user.get("is_muted", True),
            "User should be banned (is_muted should be True).",
        )

        # Step 4: Check that `punishment_date` is set
        self.assertIn(
            "punishment_date",
            updated_user,
            "punishment_date should be set when user is banned.",
        )

    def test_unmute_user(self):
        # Unmute the user first by directly setting is_banned to True and setting punishment_date
        self.users_table.update_item(
            Key={"user_id": self.user_data["user_id"]},
            UpdateExpression="set is_muted = :b, punishment_date = :d",
            ExpressionAttributeValues={
                ":b": True,
                ":d": datetime.now(pytz.timezone("US/Eastern")).isoformat(),
            },
        )

        create_user(**self.user_data)

        # Step 1: Unmute the user
        response = self.client.post(
            "/unmute_user/",
            data=json.dumps({"user_id": self.user_data["user_id"]}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data["message"],
            "User has been unmuted",
            "Unmute message should confirm unmute success.",
        )

        # Step 2: Verify the user is unmuted and punishment_date is removed
        unmuted_user = get_user(self.user_data["user_id"])
        self.assertTrue(
            unmuted_user.get("is_muted") is not True,
            "User's is_muted should be False after unban.",
        )
        self.assertFalse(
            hasattr(unmuted_user, "punishment_date"),
            "punishment_date should be removed when user is unmuted.",
        )

    def test_delete_user(self):
        # Ensure the user exists before testing deletion
        self.users_table.put_item(Item=self.user_data)

        # Step 2: Delete the user by username
        delete_result = delete_user_by_username(self.user_data["username"])
        self.assertTrue(delete_result, "User deletion failed.")

        # Verify that the user was deleted
        response = self.users_table.get_item(Key={"user_id": self.user_data["user_id"]})
        self.assertNotIn("Item", response, "User was found in DynamoDB after deletion.")

    def tearDown(self):
        # Clean up: If the test fails to delete the user, remove it manually
        try:
            self.users_table.delete_item(Key={"user_id": self.user_data["user_id"]})
        except ClientError:
            pass  # Ignore if the item was already deleted


class ForumTests(TestCase):
    def setUp(self):
        # Initialize DynamoDB resource and Threads table
        self.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")

        self.users_table = self.dynamodb.Table("Users")
        self.posts_table = self.dynamodb.Table("ForumPosts")

        # Define user data for the test
        self.user_data = {
            "user_id": "test_user_123",
            "username": "test_user123",
            "email": "test_user@example.com",
            "name": "Test User",
            "date_of_birth": "1990-01-01",
            "gender": "O",
            "password": "hashed_password",
        }
        self.threads_table = self.dynamodb.Table("ForumThreads")

        # Define thread data for the test
        self.thread_data = {
            "title": "Test Thread",
            "user_id": "test_user_123",
            "content": "This is a test thread content",
        }

    def test_create_thread(self):
        # Step 1: Create the thread
        thread = create_thread(
            title=self.thread_data["title"],
            user_id=self.thread_data["user_id"],
            content=self.thread_data["content"],
        )

        # Verify that the thread has a ThreadID and CreatedAt
        self.assertIn("ThreadID", thread, "ThreadID should be generated and set.")
        self.assertIn("CreatedAt", thread, "CreatedAt should be generated and set.")

        # Step 2: Retrieve the thread from DynamoDB to verify it was added
        response = self.threads_table.get_item(Key={"ThreadID": thread["ThreadID"]})
        self.assertIn("Item", response, "Thread not found in DynamoDB after creation.")

        created_thread = response["Item"]
        self.assertEqual(
            created_thread["Title"],
            self.thread_data["title"],
            "Thread title does not match.",
        )
        self.assertEqual(
            created_thread["UserID"],
            self.thread_data["user_id"],
            "Thread user_id does not match.",
        )
        self.assertEqual(
            created_thread["Content"],
            self.thread_data["content"],
            "Thread content does not match.",
        )
        self.assertEqual(created_thread["Likes"], 0, "Initial likes count should be 0.")
        self.assertEqual(
            created_thread["LikedBy"], [], "Initial LikedBy list should be empty."
        )

    def test_get_thread(self):
        # Step 1: Create a sample thread
        thread = create_thread(
            title=self.thread_data["title"],
            user_id=self.thread_data["user_id"],
            content=self.thread_data["content"],
        )

        # Step 2: Retrieve the thread using get_thread with matching parameters
        retrieved_thread = get_thread(
            title=thread["Title"],
            user_id=thread["UserID"],
            content=thread["Content"],
            created_at=thread["CreatedAt"],
        )

        # Step 3: Verify the retrieved thread matches the created thread
        self.assertIsNotNone(retrieved_thread, "Thread should be found.")
        self.assertEqual(
            retrieved_thread["Title"], thread["Title"], "Thread title does not match."
        )
        self.assertEqual(
            retrieved_thread["UserID"],
            thread["UserID"],
            "Thread user ID does not match.",
        )
        self.assertEqual(
            retrieved_thread["Content"],
            thread["Content"],
            "Thread content does not match.",
        )

    def test_fetch_all_users(self):
        # Add threads to the DynamoDB table for testing
        test_threads = [
            {
                "ThreadID": "201",
                "Title": "Thread 1",
                "UserID": "user_123",
                "CreatedAt": "2024-11-01T10:00:00",
                "Content": "This is thread 1 content.",
            },
            {
                "ThreadID": "202",
                "Title": "Thread 2",
                "UserID": "user_456",
                "CreatedAt": "2024-11-02T11:00:00",
                "Content": "This is thread 2 content.",
            },
            {
                "ThreadID": "203",
                "Title": "Thread 3",
                "UserID": "user_123",  # Duplicate UserID
                "CreatedAt": "2024-11-03T12:00:00",
                "Content": "This is thread 3 content.",
            },
        ]
        for thread in test_threads:
            self.threads_table.put_item(Item=thread)

        try:
            # Fetch all unique users
            users = fetch_all_users()

            # Verify that the correct number of unique users is returned
            self.assertGreater(len(users), 2)

            # Verify the unique usernames
            usernames = [user["username"] for user in users]
            self.assertIn("user_123", usernames)
            self.assertIn("user_456", usernames)

        finally:
            # Cleanup the test data
            for thread in test_threads:
                self.threads_table.delete_item(Key={"ThreadID": thread["ThreadID"]})

    def test_get_thread_details(self):
        # Add posts to the DynamoDB table for testing
        test_posts = [
            {
                "PostID": "301",
                "ThreadID": "thread_123",
                "UserID": "user_123",
                "Content": "This is a post in thread_123.",
                "CreatedAt": "2024-11-01T10:00:00",
            },
            {
                "PostID": "302",
                "ThreadID": "thread_456",
                "UserID": "user_456",
                "Content": "This is a post in thread_456.",
                "CreatedAt": "2024-11-02T11:00:00",
            },
        ]
        for post in test_posts:
            self.posts_table.put_item(Item=post)

        try:
            # Fetch details for an existing thread
            thread_details = get_thread_details("thread_123")
            self.assertIsNotNone(thread_details, "Thread details should not be None.")
            self.assertEqual(thread_details["ThreadID"], "thread_123")
            self.assertEqual(thread_details["Content"], "This is a post in thread_123.")
            self.assertEqual(thread_details["UserID"], "user_123")

            # Fetch details for a non-existing thread
            non_existing_thread_details = get_thread_details("non_existing_thread")
            self.assertIsNone(
                non_existing_thread_details,
                "Thread details for a non-existing thread should be None.",
            )

        finally:
            # Cleanup the test data
            for post in test_posts:
                self.posts_table.delete_item(
                    Key={"PostID": post["PostID"], "ThreadID": post["ThreadID"]}
                )

    def test_create_post(self):
        # Setup: Create a thread for the post to be attached to
        thread = create_thread(
            title=self.thread_data["title"],
            user_id=self.thread_data["user_id"],
            content=self.thread_data["content"],
        )
        thread_id = thread["ThreadID"]

        # Create a post in the thread
        post = create_post(thread_id, "test_user_123", "This is a test post content.")
        post_id = post["PostID"]

        try:
            # Fetch the post from DynamoDB
            post_response = self.posts_table.get_item(
                Key={"PostID": post_id, "ThreadID": thread_id}
            )

            # Assertions for the post
            self.assertIn("Item", post_response)
            self.assertEqual(post_response["Item"]["ThreadID"], thread_id)
            self.assertEqual(post_response["Item"]["UserID"], "test_user_123")
            self.assertEqual(
                post_response["Item"]["Content"], "This is a test post content."
            )

        finally:
            # Cleanup: Delete the created thread and post from DynamoDB
            self.threads_table.delete_item(Key={"ThreadID": thread_id})
            self.posts_table.delete_item(Key={"PostID": post_id, "ThreadID": thread_id})

    def test_fetch_filtered_threads(self):
        # Add threads to the DynamoDB table for testing
        test_threads = [
            {
                "ThreadID": "101",
                "Title": "General Discussion",
                "UserID": "test_user_123",
                "CreatedAt": "2024-09-02T10:00:00",
                "Section": "general",
                "Content": "This is a general discussion thread.",
                "ReplyCount": 0,
            },
            {
                "ThreadID": "102",
                "Title": "Support Needed",
                "UserID": "test_user_456",
                "CreatedAt": "2024-11-02T11:00:00",
                "Section": "support",
                "Content": "This is a support thread.",
                "ReplyCount": 3,
            },
        ]
        for thread in test_threads:
            self.threads_table.put_item(Item=thread)

        try:
            # Test filtering by section
            threads = fetch_filtered_threads(section="general")
            self.assertEqual(len(threads), 1)
            self.assertEqual(threads[0]["ThreadID"], "101")
            self.assertEqual(threads[0]["Section"], "general")

            # Test filtering by username
            threads = fetch_filtered_threads(username="test_user_456")
            self.assertEqual(len(threads), 1)
            self.assertEqual(threads[0]["UserID"], "test_user_456")

            # Test filtering by date range
            threads = fetch_filtered_threads(
                start_date="2024-09-01", end_date="2024-09-02"
            )
            self.assertEqual(len(threads), 0)

            # Test filtering by text search
            threads = fetch_filtered_threads(search_text="support")
            self.assertEqual(len(threads), 1)
            self.assertEqual(threads[0]["ThreadID"], "102")

            # Test fetching all threads
            threads = fetch_filtered_threads()
            self.assertGreater(len(threads), 0)

        finally:
            # Cleanup the test data
            for thread in test_threads:
                self.threads_table.delete_item(Key={"ThreadID": thread["ThreadID"]})

    def test_delete_post(self):
        # Add a post to the DynamoDB table for testing
        test_thread = {
            "ThreadID": "101",
            "Title": "General Discussion",
            "UserID": "test_user_123",
            "CreatedAt": "2024-09-02T10:00:00",
            "Section": "general",
            "Content": "This is a general discussion thread.",
            "ReplyCount": 0,
        }

        test_post = {
            "PostID": "401",
            "ThreadID": "101",
            "UserID": "user_123",
            "Content": "This is a test post.",
            "CreatedAt": "2024-11-01T10:00:00",
        }
        self.threads_table.put_item(Item=test_thread)
        self.posts_table.put_item(Item=test_post)

        try:
            # Verify the post exists before deletion
            response = self.posts_table.get_item(
                Key={"ThreadID": test_post["ThreadID"], "PostID": test_post["PostID"]}
            )
            self.assertIn(
                "Item", response, "Post should exist in the table before deletion."
            )

            # Call the delete_post function
            delete_result = delete_post(test_post["PostID"], test_post["ThreadID"])
            self.assertTrue(delete_result, "Post deletion should return True.")

            # Verify the post no longer exists after deletion
            response = self.posts_table.get_item(
                Key={"ThreadID": test_post["ThreadID"], "PostID": test_post["PostID"]}
            )
            self.assertNotIn(
                "Item",
                response,
                "Post should no longer exist in the table after deletion.",
            )

        finally:
            # Cleanup: Ensure the post is deleted, in case the function failed
            self.posts_table.delete_item(
                Key={"ThreadID": test_post["ThreadID"], "PostID": test_post["PostID"]}
            )

            self.threads_table.delete_item(Key={"ThreadID": test_post["ThreadID"]})

    def test_delete_thread_by_id(self):
        # Step 1: Create a sample thread
        thread = create_thread(
            title=self.thread_data["title"],
            user_id=self.thread_data["user_id"],
            content=self.thread_data["content"],
        )
        thread_id = thread["ThreadID"]

        # Verify the thread exists in DynamoDB
        response = self.threads_table.get_item(Key={"ThreadID": thread_id})
        self.assertIn(
            "Item", response, "Thread should exist in DynamoDB before deletion."
        )

        # Step 2: Delete the thread
        delete_result = delete_thread_by_id(thread_id)
        self.assertTrue(delete_result, "Thread deletion failed.")

        # Step 3: Verify the thread is deleted
        response = self.threads_table.get_item(Key={"ThreadID": thread_id})
        self.assertNotIn("Item", response, "Thread should be deleted from DynamoDB.")

    def test_fetch_all_threads(self):

        self.test_threads = [
            {
                "ThreadID": "1",
                "Title": "Test",
                "UserID": "test_user_123",
                "CreatedAt": "2024-11-01T10:00:00",
                "Content": "Test",
            },
        ]
        for thread in self.test_threads:
            self.threads_table.put_item(Item=thread)

        # Call the function
        threads = fetch_all_threads()

        # Check the first thread of test user's threads' properties
        thread = next((t for t in threads if t.get("UserID") == "test_user_123"), None)
        self.assertEqual(thread["ThreadID"], "1")
        self.assertEqual(thread["ReplyCount"], 0)
        self.assertEqual(thread["LastPostUser"], "No replies yet")
        self.assertEqual(
            thread["CreatedAt"], datetime.fromisoformat("2024-11-01T10:00:00")
        )

    def test_fetch_thread(self):
        self.test_thread = {
            "ThreadID": "123",
            "Title": "Test Thread",
            "UserID": "test_user_123",
            "CreatedAt": "2024-11-14T10:00:00",
        }
        self.threads_table.put_item(Item=self.test_thread)

        thread = fetch_thread("123")

        # Assertions to verify the thread details
        self.assertIsNotNone(thread)
        self.assertEqual(thread["ThreadID"], "123")
        self.assertEqual(thread["Title"], "Test Thread")
        self.assertEqual(thread["CreatedAt"], "2024-11-14T10:00:00")

        # Call the function to fetch a non-existing thread
        thread = fetch_thread("999")

        # Assertion to verify the function returns None
        self.assertIsNone(thread)

    def test_get_section_stats(self):
        # Add threads to the DynamoDB table for testing
        test_threads = [
            {
                "ThreadID": "501",
                "Title": "Thread 1",
                "UserID": "user_123",
                "Section": "general",
                "CreatedAt": "2024-11-01T10:00:00",
                "PostCount": 5,
            },
            {
                "ThreadID": "502",
                "Title": "Thread 2",
                "UserID": "user_456",
                "Section": "general",
                "CreatedAt": "2024-11-02T11:00:00",
                "PostCount": 2,
            },
            {
                "ThreadID": "503",
                "Title": "Thread 3",
                "UserID": "user_789",
                "Section": "support",
                "CreatedAt": "2024-11-03T12:00:00",
                "PostCount": 7,
            },
        ]
        for thread in test_threads:
            self.threads_table.put_item(Item=thread)

        try:
            # Fetch stats for the "general" section
            stats = get_section_stats("general")

            # Verify thread count is greater than 1
            self.assertGreater(stats["thread_count"], 1)

            # Verify post count is greater than 6
            self.assertGreater(stats["post_count"], 6)

            # Verify the latest thread details
            latest_thread = stats["latest_thread"]
            self.assertEqual(latest_thread["title"], "Thread 2")
            self.assertEqual(latest_thread["author"], "user_456")
            self.assertEqual(latest_thread["thread_id"], "502")
            self.assertEqual(
                latest_thread["created_at"],
                datetime.fromisoformat("2024-11-02T11:00:00"),
            )

            # Fetch stats for a section with no threads
            empty_section_stats = get_section_stats("non_existing_section")
            self.assertEqual(empty_section_stats["thread_count"], 0)
            self.assertEqual(empty_section_stats["post_count"], 0)
            self.assertEqual(
                empty_section_stats["latest_thread"]["title"], "No threads"
            )
            self.assertEqual(empty_section_stats["latest_thread"]["author"], "N/A")

        finally:
            # Cleanup the test data
            for thread in test_threads:
                self.threads_table.delete_item(Key={"ThreadID": thread["ThreadID"]})

    def tearDown(self):
        delete_threads_by_user("test_user_123")


# ##########################################################
#       TEST CASE FOR GOOGLE AUTHENTICATION               #
# ##########################################################
# class GoogleAuthTestCase(TestCase):
#     @classmethod
#     def setUpClass(cls):
#         super().setUpClass()
#         cls.client = Client()

#     @patch("FitOn.views.Flow")
#     def test_authorize_google_fit(self, mock_flow):
#         # Mock the Flow object
#         mock_instance = mock_flow.from_client_config.return_value
#         mock_instance.authorization_url.return_value = (
#             "http://mock-auth-url",
#             "mock-state",
#         )

#         # Simulate a GET request to the authorization view
#         response = self.client.get(reverse("authorize_google_fit"))

#         # Save the session explicitly
#         session = self.client.session
#         session["google_fit_state"] = "mock-state"
#         session.save()

#         # Assertions
#         self.assertEqual(response.status_code, 302)  # Check redirect status code
#         self.assertIn("http://mock-auth-url", response.url)  # Verify redirection URL
#         self.assertEqual(session["google_fit_state"], "mock-state")  # Verify the value

#     @patch("FitOn.views.get_user")
#     @patch("FitOn.views.Flow")
#     @patch("FitOn.views.Credentials")

#     def test_callback_google_fit(self, mock_credentials, mock_flow, mock_get_user):
#         # Set up a mock user return value
#         mock_get_user.return_value = {
#             "name": "Test User",
#             "email": "testuser@example.com",
#             "gender": "Other",
#             "date_of_birth": "2000-01-01",
#             "phone_number": "1234567890",
#             "address": "Test Address",
#             "bio": "Test Bio",
#             "country_code": "91",
#         }

#         # Set up the mock credentials
#         mock_creds = MagicMock(spec=Credentials)
#         mock_creds.token = "mock-token"
#         mock_creds.refresh_token = "mock-refresh-token"
#         mock_creds.token_uri = "mock-token-uri"
#         mock_creds.client_id = "mock-client-id"
#         mock_creds.client_secret = "mock-client-secret"
#         mock_creds.scopes = SCOPES

#         # Mock the Flow object and its methods
#         mock_instance = mock_flow.from_client_config.return_value
#         mock_instance.fetch_token.return_value = None
#         mock_instance.credentials = mock_creds

#         # Set a user ID and state in the session
#         session = self.client.session
#         session["user_id"] = "mock_user_id"
#         session["google_fit_state"] = "mock-state"
#         session.save()

#         # Simulate a GET request to the callback view
#         response = self.client.get(reverse("callback_google_fit"))

#         # Assertions
#         self.assertEqual(response.status_code, 200)
#         self.assertTemplateUsed(response, "profile.html")
#         self.assertIn("Signed in Successfully", response.content.decode())
#         self.assertTrue(response.context["login_success"])
#         self.assertIsInstance(response.context["form"], ProfileForm)

#     @classmethod
#     def tearDownClass(cls):
#         super().tearDownClass()


# class GoogleAuthDelinkTestCase(TestCase):
#     @classmethod
#     def setUpClass(cls):
#         super().setUpClass()
#         cls.client = Client()

#     def setUp(self):
#         # Simulate session with credentials for the delink test
#         session = self.client.session
#         session["credentials"] = {
#             "token": "mock-token",
#             "refresh_token": "mock-refresh-token",
#             "token_uri": "mock-token-uri",
#             "client_id": "mock-client-id",
#             "client_secret": "mock-client-secret",
#             "scopes": ["mock-scope"],
#         }
#         session.save()

#     @patch("FitOn.views.requests.post")
#     def test_delink_google_fit(self, mock_post):
#         # Mock the response for the revoke endpoint
#         mock_post.return_value.status_code = 200  # Simulate successful revocation

#         response = self.client.post(reverse("delink_google_fit"), follow=True)

#         # Assertions
#         self.assertEqual(response.status_code, 200)  # Final status code after redirects

#         # Verify that the session no longer contains credentials
#         session = self.client.session
#         self.assertNotIn("credentials", session)

#         # Check if the success message is added to the messages framework
#         messages_list = list(get_messages(response.wsgi_request))
#         print("Messages list:", messages_list)
#         self.assertTrue(
#             any(
#                 message.message == "Your Google account has been successfully delinked."
#                 and message.level == messages.SUCCESS
#                 for message in messages_list
#             )
#         )

#         # Check if the revocation endpoint was called
#         mock_post.assert_called_once_with(
#             "https://accounts.google.com/o/oauth2/revoke",
#             params={"token": "mock-token"},
#             headers={"content-type": "application/x-www-form-urlencoded"},
#         )

#     def tearDown(self):
#         # Clear the session and any test data after each test
#         session = self.client.session
#         if "credentials" in session:
#             del session["credentials"]
#             session.save()

#     @classmethod
#     def tearDownClass(cls):
#         super().tearDownClass()


###########################################################
#       TEST CASEs FOR PASSWORD RESET              #
###########################################################


# class PasswordResetTests(TestCase):
#     @classmethod
#     @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
#     def setUpClass(cls):
#         super().setUpClass()
#         cls.client = Client()

#         # Set up connection to actual DynamoDB tables
#         cls.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
#         cls.users_table = cls.dynamodb.Table("Users")
#         cls.password_reset_table = cls.dynamodb.Table("PasswordResetRequests")

#     def setUp(self):
#         # Clear outbox for each test
#         mail.outbox = []

#         # Create a mock user for testing in the actual Users table
#         self.mock_user = MockUser(
#             {
#                 "user_id": "mock_user_id",
#                 "username": "mockuser",
#                 "email": "mockuser@example.com",
#                 "password": make_password("mockpassword"),
#                 "is_active": True,
#             }
#         )

#         # Insert the mock user into the Users table
#         self.__class__.users_table.put_item(Item=self.mock_user.__dict__)
#         print("Mock user inserted into DynamoDB for testing.")

#     def tearDown(self):
#         # Delete the mock user from the Users and PasswordResetRequests tables
#         self.__class__.users_table.delete_item(Key={"user_id": self.mock_user.user_id})
#         self.__class__.password_reset_table.delete_item(
#             Key={"user_id": self.mock_user.user_id}
#         )

#         # Clear the email outbox after each test
#         mail.outbox = []
#         super().tearDown()

#     @classmethod
#     def tearDownClass(cls):
#         # Any additional cleanup at the class level can go here
#         super().tearDownClass()

#     def test_password_reset_request_invalid_email(self):
#         # Test with an email that does not exist in the database
#         self.client.post(
#             reverse("password_reset_request"), {"email": "nonexistent@example.com"}
#         )
#         print("Testing password reset with a nonexistent email.")

#         # Ensure no email was sent
#         self.assertEqual(
#             len(mail.outbox), 0, "Expected no email to be sent for non-existent email."
#         )

# def test_password_reset_request_valid_email(self):
#     # Test with the mock user's email
#     self.client.post(
#         reverse("password_reset_request"), {"email": self.mock_user.email}
#     )

#     # Ensure an email was sent
#     self.assertEqual(len(mail.outbox), 1, "Expected exactly one email to be sent.")
#     email = mail.outbox[0]
#     self.assertEqual(email.to, [self.mock_user.email])

# def test_password_reset_link_in_email(self):
#     # Test if the password reset link is in the email
#     self.client.post(
#         reverse("password_reset_request"), {"email": self.mock_user.email}
#     )
#     self.assertEqual(len(mail.outbox), 1, "Expected one email in the outbox")
#     email = mail.outbox[0]

#     # Check if the email contains a reset link
#     self.assertIn("reset your password", email.body.lower())
#     print(f"Password reset link sent to: {email.to}")

# def test_password_reset_confirm_with_valid_token(self):
#     # Generate a valid token for the mock user
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

#     # Test accessing the password reset confirm page with a valid token
#     response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
#     self.assertEqual(response.status_code, 200)
#     self.assertContains(response, "Set New Password")

# def test_password_reset_confirm_with_invalid_token(self):
#     # Generate an invalid token and test the reset confirm page
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))
#     invalid_token = "invalid-token"

#     response = self.client.get(
#         reverse("password_reset_confirm", args=[uid, invalid_token])
#     )
#     self.assertEqual(response.status_code, 200)
#     self.assertContains(
#         response, "The password reset link is invalid or has expired."
#     )

# def test_password_reset_mismatched_passwords(self):
#     # Generate a valid token
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

#     # Post mismatched passwords
#     response = self.client.post(
#         reverse("password_reset_confirm", args=[uid, token]),
#         {"new_password": "newpassword123", "confirm_password": "wrongpassword"},
#     )
#     self.assertContains(response, "Passwords do not match.", status_code=200)

# def test_successful_password_reset(self):
#     # Generate a valid token and UID
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

#     # Successfully reset the password
#     response = self.client.post(
#         reverse("password_reset_confirm", args=[uid, token]),
#         {"new_password": "newpassword123", "confirm_password": "newpassword123"},
#         follow=True,
#     )
#     self.assertRedirects(response, reverse("password_reset_complete"))

#     # Verify new password by attempting to log in
#     updated_user = get_user_by_email(self.mock_user.email)
#     self.assertTrue(
#         updated_user and updated_user.password, "Password reset was not successful."
#     )

# def test_password_reset_complete_view(self):
#     # Test if the password reset complete page renders correctly
#     response = self.client.get(reverse("password_reset_complete"))
#     self.assertEqual(response.status_code, 200)
#     self.assertContains(response, "Your password has been successfully reset.")

# def test_password_reset_throttling(self):
#     # First password reset request
#     response = self.client.post(
#         reverse("password_reset_request"), {"email": self.mock_user.email}
#     )
#     self.assertEqual(len(mail.outbox), 1, "Expected exactly one email to be sent.")

#     # Attempt a second request immediately, which should be throttled
#     response = self.client.post(
#         reverse("password_reset_request"), {"email": self.mock_user.email}
#     )
#     self.assertContains(response, "Please wait", status_code=200)
#     self.assertEqual(
#         len(mail.outbox), 1, "No additional email should be sent due to throttling."
#     )

# def test_password_reset_request_case_sensitive_email(self):
#     # Enter a valid email with incorrect casing
#     self.client.post(
#         reverse("password_reset_request"), {"email": "MockUser@example.com"}
#     )
#     # No email should be sent due to case sensitivity
#     self.assertEqual(
#         len(mail.outbox),
#         0,
#         "Expected no email to be sent due to case-sensitive mismatch.",
#     )
#     print(
#         "Tested case-sensitive email matching: no email sent for mismatched case."
#     )

# def test_password_reset_request_inactive_user(self):
#     self.mock_user.is_active = False
#     self.__class__.users_table.put_item(Item=self.mock_user.__dict__)

#     response = self.client.post(
#         reverse("password_reset_request"), {"email": self.mock_user.email}
#     )
#     self.assertContains(
#         response, "The email you entered is not registered", status_code=200
#     )
#     self.assertEqual(
#         len(mail.outbox), 0, "No email should be sent for an inactive user."
#     )

# @patch(
#     "django.contrib.auth.tokens.default_token_generator.check_token",
#     return_value=False,
# )
# def test_expired_token_password_reset_confirm(self, mock_check_token):
#     # Generate a valid token with the current time
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

#     # Mock the token check to simulate an expired token
#     print("Simulating expired token by forcing check_token to return False.")

#     # Attempt to reset password with the "expired" token
#     response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
#     self.assertContains(
#         response,
#         "The password reset link is invalid or has expired.",
#         status_code=200,
#     )

# def test_password_reset_email_content(self):
#     self.client.post(
#         reverse("password_reset_request"), {"email": self.mock_user.email}
#     )
#     self.assertEqual(len(mail.outbox), 1, "Expected one email to be sent.")
#     email = mail.outbox[0]

#     # Check if email contains specific expected content
#     self.assertIn("reset your password", email.body.lower())
#     self.assertIn(
#         self.mock_user.username, email.body
#     )  # Username should be included in the email
#     reset_url_fragment = reverse(
#         "password_reset_confirm",
#         args=[
#             urlsafe_base64_encode(force_bytes(self.mock_user.user_id)),
#             default_token_generator.make_token(self.mock_user),
#         ],
#     )
#     self.assertIn(reset_url_fragment, email.body)

# def test_login_with_new_password_after_reset(self):
#     # Generate a valid token and reset the password
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))
#     new_password = "newpassword123"

#     response = self.client.post(
#         reverse("password_reset_confirm", args=[uid, token]),
#         {"new_password": new_password, "confirm_password": new_password},
#         follow=True,
#     )
#     self.assertRedirects(response, reverse("password_reset_complete"))

#     # Now attempt to log in with the new password
#     response = self.client.post(
#         reverse("login"),
#         {"username": self.mock_user.username, "password": new_password},
#     )
#     self.assertRedirects(response, reverse("homepage"))

# def test_password_reset_confirm_invalid_uid(self):
#     # Generate a valid token but use an invalid UID
#     invalid_uid = "invalid-uid"
#     token = default_token_generator.make_token(self.mock_user)

#     response = self.client.get(
#         reverse("password_reset_confirm", args=[invalid_uid, token])
#     )
#     self.assertContains(
#         response,
#         "The password reset link is invalid or has expired.",
#         status_code=200,
#    )

# check
# def test_single_use_token(self):
#     # Generate a valid token and UID
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

#     # First reset attempt with valid token
#     response = self.client.post(
#         reverse("password_reset_confirm", args=[uid, token]),
#         {"new_password": "newpassword123", "confirm_password": "newpassword123"},
#     )
#     self.assertRedirects(response, reverse("password_reset_complete"))

#     # Second reset attempt with the same token should fail
#     response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
#     self.assertContains(
#         response,
#         "The password reset link is invalid or has expired.",
#         status_code=200,
#     )

# def test_password_reset_request_with_html_injection(self):
#     response = self.client.post(
#         reverse("password_reset_request"),
#         {"email": "<script>alert('xss')</script>@example.com"},
#     )
#     self.assertContains(response, "Enter a valid email address.", status_code=200)
#     self.assertEqual(
#         len(mail.outbox),
#         0,
#         "No email should be sent for an invalid email with HTML.",
#     )

# def test_password_reset_confirm_access_without_token(self):
#     response = self.client.get(
#         reverse("password_reset_confirm", args=["invalid-uid", "invalid-token"])
#     )
#     self.assertContains(
#         response,
#         "The password reset link is invalid or has expired.",
#         status_code=200,
#     )

# def test_password_reset_request_template(self):
#     response = self.client.get(reverse("password_reset_request"))
#     self.assertTemplateUsed(response, "password_reset_request.html")
#     self.assertContains(response, "Reset Password")

# def test_password_reset_confirm_template(self):
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))
#     response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
#     self.assertTemplateUsed(response, "password_reset_confirm.html")
#     self.assertContains(response, "Set New Password")

# def test_password_reset_request_with_malformed_email(self):
#     # Test with a malformed email address
#     response = self.client.post(
#         reverse("password_reset_request"),
#         {"email": "user@.com"},
#     )
#     self.assertContains(response, "Enter a valid email address.", status_code=200)
#     self.assertEqual(
#         len(mail.outbox),
#         0,
#         "No email should be sent for a malformed email address.",
#     )

# def test_password_reset_accessibility_without_login(self):
#     # Access the password reset request page
#     response = self.client.get(reverse("password_reset_request"))
#     self.assertEqual(response.status_code, 200)
#     self.assertContains(response, "Reset Password")

#     # Generate valid token and UID
#     token = default_token_generator.make_token(self.mock_user)
#     uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

#     # Access the password reset confirmation page with a valid token
#     response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
#     self.assertEqual(response.status_code, 200)
#     self.assertContains(response, "Set New Password")

# def test_password_reset_request_with_injection_attempt(self):
#     injection_email = "user@example.com'; DROP TABLE Users; --"
#     response = self.client.post(
#         reverse("password_reset_request"), {"email": injection_email}
#     )
#     self.assertEqual(
#         len(mail.outbox), 0, "No email should be sent for an injection attempt."
#     )
#     self.assertContains(response, "Enter a valid email address.", status_code=200)


###########################################################
#       TEST CASEs FOR VARIOUS FORMS                      #
###########################################################


class SignUpFormTest(TestCase):

    def test_passwords_match(self):
        form_data = {
            "username": "testuser",
            "email": "testuser@example.com",
            "name": "Test User",
            "date_of_birth": "2000-01-01",
            "gender": "M",
            "height": "183",
            "weight": "80",
            "password": "strongpassword123",
            "confirm_password": "strongpassword123",
        }
        form = SignUpForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_passwords_do_not_match(self):
        form_data = {
            "username": "testuser",
            "email": "testuser@example.com",
            "name": "Test User",
            "date_of_birth": "2000-01-01",
            "gender": "M",
            "height": "183",
            "weight": "80",
            "password": "strongpassword123",
            "confirm_password": "differentpassword",
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Passwords do not match.", form.errors["__all__"])


class SetNewPasswordFormTest(TestCase):

    def test_passwords_match(self):
        form_data = {
            "new_password": "newstrongpassword123",
            "confirm_password": "newstrongpassword123",
        }
        form = SetNewPasswordForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_passwords_do_not_match(self):
        form_data = {
            "new_password": "newstrongpassword123",
            "confirm_password": "differentpassword",
        }
        form = SetNewPasswordForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Passwords do not match.", form.errors["__all__"])


class ProfileFormTest(TestCase):

    def test_valid_form_with_country_code_and_phone(self):
        form_data = {
            "name": "John Doe",
            "date_of_birth": "1990-01-01",
            "email": "johndoe@example.com",
            "gender": "M",  # Use a valid value from GENDER_OPTIONS
            "country_code": "+1",  # Replace with a valid choice from COUNTRY_CODES
            "phone_number": "1234567890",
        }
        form = ProfileForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_valid_form_without_phone_and_country_code(self):
        form_data = {
            "name": "John Doe",
            "date_of_birth": "1990-01-01",
            "email": "johndoe@example.com",
            "gender": "M",  # Use a valid value from GENDER_OPTIONS
        }
        form = ProfileForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_invalid_phone_number_non_digits(self):
        form_data = {
            "name": "John Doe",
            "date_of_birth": "1990-01-01",
            "email": "johndoe@example.com",
            "gender": "M",  # Use a valid value from GENDER_OPTIONS
            "country_code": "+1",  # Replace with a valid choice from COUNTRY_CODES
            "phone_number": "abcd1234",
        }
        form = ProfileForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn(
            "Phone number should contain only digits.", form.errors["phone_number"]
        )

    def test_country_code_without_phone_number(self):
        form_data = {
            "name": "John Doe",
            "date_of_birth": "1990-01-01",
            "email": "johndoe@example.com",
            "gender": "M",  # Use a valid value from GENDER_OPTIONS
            "country_code": "+1",  # Replace with a valid choice from COUNTRY_CODES
        }
        form = ProfileForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn(
            "Both country code and phone number must be provided together",
            form.errors["phone_number"],
        )
        self.assertIn(
            "Both country code and phone number must be provided together",
            form.errors["country_code"],
        )

    def test_phone_number_without_country_code(self):
        form_data = {
            "name": "John Doe",
            "date_of_birth": "1990-01-01",
            "email": "johndoe@example.com",
            "gender": "M",  # Use a valid value from GENDER_OPTIONS
            "phone_number": "1234567890",
        }
        form = ProfileForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn(
            "Both country code and phone number must be provided together",
            form.errors["phone_number"],
        )
        self.assertIn(
            "Both country code and phone number must be provided together",
            form.errors["country_code"],
        )


class ValidateFileExtensionTest(TestCase):

    def test_valid_pdf_file(self):
        valid_file = SimpleUploadedFile("document.pdf", b"file_content")
        try:
            validate_file_extension(valid_file)
        except ValidationError:
            self.fail("validate_file_extension raised ValidationError unexpectedly!")

    # def test_invalid_file_extension(self):
    #     invalid_file = SimpleUploadedFile("document.txt", b"file_content", content_type="text/plain")
    #     # Attempt to call the validation function
    #     try:
    #         validate_file_extension(invalid_file)
    #     except ValidationError as e:
    #         # Check if the exception contains the expected message
    #         self.assertListEqual(e.messages, ["Only PDF files are allowed."])
    #         return  # Test passed
    #     self.fail("validate_file_extension did not raise ValidationError")


############################
# Tests for views #
############################


class HomepageViewTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def test_homepage_with_username(self):
        request = self.factory.get("/")
        request.session = {"username": "sg8002"}  # Directly set the session

        response = homepage(request)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, "sg8002"
        )  # Check that "JohnDoe" is in the response content

    def test_homepage_without_username(self):
        request = self.factory.get("/")
        request.session = {}  # No username in the session

        response = homepage(request)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, "Guest"
        )  # Check that "Guest" is in the response content


class AddMessageTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def _attach_middlewares(self, request):
        """Helper method to attach SessionMiddleware and MessageMiddleware to the request."""
        session_middleware = SessionMiddleware(lambda req: None)
        session_middleware.process_request(request)
        request.session.save()  # Save the session to initialize it

        message_middleware = MessageMiddleware(lambda req: None)
        message_middleware.process_request(request)

    def test_add_message(self):
        # Create a mock request
        request = self.factory.get("/")
        self._attach_middlewares(request)  # Attach both middlewares

        # Call the add_message function
        add_message(request, level=25, message="Test Message")

        # Retrieve the messages from the request
        messages = list(get_messages(request))

        # Assertions
        self.assertEqual(len(messages), 0)


class PerformRedirectTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    async def test_perform_redirect(self):
        # Call the async perform_redirect function
        response = await perform_redirect(
            "homepage"
        )  # Use a valid URL name from your project

        # Assertions
        self.assertEqual(
            response.url, "/home/"
        )  # Replace "/" with the actual URL for "homepage"


class LoginViewTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        # Create a user in DynamoDB for testing
        self.username = "testuser"
        self.password = "correctpassword"
        hashed_password = make_password(self.password)
        create_user(
            self.username,
            self.username,
            "",
            "Test User",
            "",
            "",
            "",
            "",
            hashed_password,
        )

    def tearDown(self):
        # Clean up the test user from DynamoDB
        delete_user_by_username(self.username)

    def test_login_valid_user_and_password(self):
        # Create a POST request with valid credentials
        request = self.factory.post(
            "/", {"username": self.username, "password": self.password}
        )
        request.session = {}

        # Call the login view
        response = login(request)

        # Check if the response is a redirect to the homepage
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("homepage"))
        self.assertIn("username", request.session)
        self.assertEqual(request.session["username"], self.username)

    def test_login_user_does_not_exist(self):
        # Create a POST request with a non-existent username
        request = self.factory.post(
            "/", {"username": "nonexistentuser", "password": "password"}
        )
        request.session = {}

        # Call the login view
        response = login(request)

        # Check for the correct error message in the response
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "User does not exist.")

    def test_login_invalid_password(self):
        # Create a POST request with an incorrect password
        request = self.factory.post(
            "/", {"username": self.username, "password": "wrongpassword"}
        )
        request.session = {}

        # Call the login view
        response = login(request)

        # Check for the correct error message in the response
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid password. Please try again.")


class CustomLogoutViewTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def _attach_session(self, request):
        """Helper method to attach a session to the request using SessionMiddleware."""
        middleware = SessionMiddleware(
            lambda req: None
        )  # Pass a dummy get_response function
        middleware.process_request(request)
        request.session.save()  # Save the session to initialize it

    def test_custom_logout(self):
        # Create a mock request and attach a session
        request = self.factory.get("/")
        self._attach_session(request)

        # Set some session data
        request.session["username"] = "testuser"
        request.session["user_id"] = "123"

        # Call the custom_logout view
        response = custom_logout(request)

        # Assertions
        self.assertEqual(response.status_code, 302)  # Check for redirect
        self.assertEqual(response["Location"], reverse("login"))  # Check redirect URL

        # Check that the session is flushed (no data should remain)
        self.assertNotIn("username", request.session)
        self.assertNotIn("user_id", request.session)

        # Check cache control headers
        self.assertEqual(
            response["Cache-Control"], "no-cache, no-store, must-revalidate"
        )
        self.assertEqual(response["Pragma"], "no-cache")
        self.assertEqual(response["Expires"], "0")


class SignUpViewTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        # User data for testing
        self.username = "newuser"
        self.email = "newuser@example.com"
        self.name = "New User"
        self.date_of_birth = "2000-01-01"
        self.gender = "M"
        self.height = ("180",)
        self.weight = "83"
        self.password = "newpassword"

    def tearDown(self):
        # Clean up the test user from DynamoDB
        delete_user_by_username(self.username)

    def test_signup_valid_data(self):
        # Create a POST request with valid sign-up data
        request = self.factory.post(
            "/signup/",
            {  # Use "/signup/" instead of "/"
                "username": self.username,
                "email": self.email,
                "name": self.name,
                "date_of_birth": self.date_of_birth,
                "gender": self.gender,
                "height": self.height,
                "weight": self.weight,
                "password": self.password,
                "confirm_password": self.password,  # Ensure passwords match
            },
        )
        request.session = {}

        # Call the signup view
        response = signup(request)

        # print(response)

        # Check if the response is a redirect to the homepage
        self.assertEqual(response.status_code, 302, "Expected redirect did not occur.")
        self.assertEqual(response.url, reverse("homepage"))
        self.assertIn("username", request.session)
        self.assertEqual(request.session["username"], self.username)

    def test_signup_invalid_data(self):
        # Create a POST request with invalid data (e.g., missing required fields)
        request = self.factory.post(
            "/signup/",
            {
                "username": "",
                "email": "invalidemail",
                "name": "",
                "date_of_birth": "",
                "gender": "",
                "height": "",
                "weight": "",
                "password": "short",
                "confirm_password": "different",  # Passwords do not match
            },
        )
        request.session = {}

        # Call the signup view
        response = signup(request)

        # Check that the response does not redirect and the form has errors
        self.assertEqual(response.status_code, 200)
        self.assertIn("This field is required.", response.content.decode())
        self.assertIn("Enter a valid email address.", response.content.decode())
        self.assertIn("Passwords do not match.", response.content.decode())


class ForumViewTests(TestCase):
    def setUp(self):
        # Initialize DynamoDB resources and tables
        self.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
        self.users_table = self.dynamodb.Table("Users")
        self.threads_table = self.dynamodb.Table("ForumThreads")
        self.posts_table = self.dynamodb.Table("ForumPosts")

        # Add test user
        self.user_data = {
            "user_id": "test_user_123",
            "username": "test_user123",
            "email": "test_user@example.com",
            "name": "Test User",
            "date_of_birth": "1990-01-01",
            "gender": "O",
            "is_banned": False,
            "is_muted": False,
            "password": "hashed_password",
        }
        self.users_table.put_item(Item=self.user_data)

        # Add test threads
        self.test_threads = [
            {
                "ThreadID": "101",
                "Title": "General Thread",
                "UserID": "test_user_123",
                "Section": "General",
                "CreatedAt": "2024-11-01T10:00:00",
            },
            {
                "ThreadID": "102",
                "Title": "Workout Advice",
                "UserID": "test_user_123",
                "Section": "Workout Suggestions",
                "CreatedAt": "2024-11-02T11:00:00",
            },
        ]
        for thread in self.test_threads:
            self.threads_table.put_item(Item=thread)

    def add_middleware(self, request):
        """
        Helper function to add session and message middleware to the request.
        """
        # Pass a no-op lambda as the get_response callable
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()

        message_middleware = MessageMiddleware(lambda r: None)
        message_middleware.process_request(request)
        request.session.save()

    def test_forum_view(self):
        factory = RequestFactory()

        # Simulate a GET request to the forums page with a valid user session
        request = factory.get(
            reverse("forum"),
            {
                "username": "test_user_123",
                "type": "all",
                "start_date": "",
                "end_date": "",
            },
        )
        self.add_middleware(request)
        request.session["username"] = "test_user_123"

        # Call the forum_view function
        response = forum_view(request)

        # Check if the response is a redirect
        if response.status_code == 302:
            # Assert the redirect location
            self.assertIn("/login", response["Location"])
            return

        # # Assertions for the response
        # self.assertEqual(response.status_code, 200)
        # self.assertIn("threads", response.context_data)
        # self.assertIn("users", response.context_data)
        # self.assertIn("section_stats", response.context_data)

        # # Assertions for threads
        # threads = response.context_data["threads"]
        # self.assertGreater(len(threads), 1)
        # self.assertEqual(threads[0]["Title"], "General Thread")
        # self.assertEqual(threads[1]["Title"], "Workout Advice")

        # # Assertions for users
        # users = response.context_data["users"]
        # self.assertGreater(len(users), 0)
        # usernames = [user["username"] for user in users]
        # self.assertIn("test_user_123", usernames)

        # # Assertions for section stats
        # section_stats = response.context_data["section_stats"]
        # self.assertIn("General", section_stats)
        # self.assertIn("Workout Suggestions", section_stats)

    def tearDown(self):
        # Cleanup the test data
        self.users_table.delete_item(Key={"user_id": self.user_data["user_id"]})
        for thread in self.test_threads:
            self.threads_table.delete_item(Key={"ThreadID": thread["ThreadID"]})


###################################################
# Test Case For rds.py
###################################################


class TestConvertToMysqlDatetime(TestCase):
    def test_valid_date_conversion(self):
        """
        Test the function with a valid date string in the specified format.
        """
        input_date = "Dec 03, 11 PM"
        expected_output = "2024-12-03 23:00:00"
        self.assertEqual(convert_to_mysql_datetime(input_date), expected_output)

    def test_valid_date_am(self):
        """
        Test the function with a valid date string for AM time.
        """
        input_date = "Jan 15, 9 AM"
        expected_output = "2024-01-15 09:00:00"
        self.assertEqual(convert_to_mysql_datetime(input_date), expected_output)

    def test_invalid_date_format(self):
        """
        Test the function with an invalid date string format.
        """
        input_date = "03-12-2024 23:00"
        with self.assertRaises(ValueError):
            convert_to_mysql_datetime(input_date)

    def test_empty_date_string(self):
        """
        Test the function with an empty date string.
        """
        input_date = ""
        with self.assertRaises(ValueError):
            convert_to_mysql_datetime(input_date)

    def test_incomplete_date_string(self):
        """
        Test the function with an incomplete date string.
        """
        input_date = "Dec 03"
        with self.assertRaises(ValueError):
            convert_to_mysql_datetime(input_date)


class TestGetSecretRds(IsolatedAsyncioTestCase):
    async def test_get_secret_rds(self):
        # Expected secret values (match this with the secret in AWS Secrets Manager)
        expected_secret = {
            "host": "fiton.cxkgakkyk8zs.us-west-2.rds.amazonaws.com",
            "database": "fiton",
            "port": 3306,
            "password": "Fiton#swe-2024",
            "username": "admin",
        }

        # Call the actual function
        result = await get_secret_rds()

        # Assert the results
        self.assertEqual(result["host"], expected_secret["host"])
        self.assertEqual(result["database"], expected_secret["database"])
        self.assertEqual(result["port"], str(expected_secret["port"]))
        self.assertEqual(result["password"], expected_secret["password"])
        self.assertEqual(result["username"], expected_secret["username"])


class TestCreateConnection(IsolatedAsyncioTestCase):
    async def test_create_connection(self):
        """
        Test the create_connection function with a live MySQL database.
        Ensure the connection is successfully established.
        """
        conn = None
        try:
            # Call the create_connection function
            conn = await create_connection()

            # Verify the connection is established
            self.assertIsNotNone(conn, "Connection object is None.")
            # self.assertTrue(conn.open, "Connection is not open.")

            # Execute a simple query to test the connection
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT DATABASE();")
                result = await cursor.fetchone()
                self.assertIsNotNone(result, "Query returned no result.")
                self.assertEqual(result[0], "fiton", "Connected to the wrong database.")

        except aiomysql.Error as e:
            self.fail(f"Database connection failed: {e}")

        finally:
            # Ensure the connection is closed even if an exception occurs
            if conn:
                conn.close()


# Assuming create_table and insert_data are imported


class TestDatabaseOperations(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up a database connection before each test."""
        self.conn = await create_connection()

    async def asyncTearDown(self):
        """Clean up database connection after each test."""
        async with self.conn.cursor() as cursor:
            # Drop the test table to clean up
            await cursor.execute("DROP TABLE IF EXISTS test_table;")
        await self.conn.commit()
        self.conn.close()

    async def test_create_table(self):
        """Test the create_table function."""
        table_sql = """
        CREATE TABLE test_table (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            age INT NOT NULL
        );
        """
        # Call the function to create the table
        await create_table(self.conn, table_sql)

        # Verify the table was created
        async with self.conn.cursor() as cursor:
            await cursor.execute("SHOW TABLES LIKE 'test_table';")
            result = await cursor.fetchone()
            self.assertIsNotNone(result, "Table test_table was not created.")

    async def test_insert_data(self):
        """Test the insert_data function."""
        # Create the test table
        table_sql = """
        CREATE TABLE test_table (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            age INT NOT NULL
        );
        """
        await create_table(self.conn, table_sql)

        # Insert data into the table
        insert_query = "INSERT INTO test_table (name, age) VALUES (%s, %s);"
        test_data = ("Alice", 30)
        await insert_data(self.conn, insert_query, test_data)

        # Verify the data was inserted
        async with self.conn.cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM test_table WHERE name = %s;", (test_data[0],)
            )
            result = await cursor.fetchone()

        self.assertIsNotNone(result, "Data was not inserted into test_table.")
        self.assertEqual(result[1], "Alice", "Inserted name does not match.")
        self.assertEqual(result[2], 30, "Inserted age does not match.")


class TestHealthMetricTables(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up a database connection before each test."""
        self.conn = await create_connection()

    async def asyncTearDown(self):
        """Clean up database connection after each test."""
        async with self.conn.cursor() as cursor:
            # Drop the test tables to clean up
            tables = [
                "STEPS",
                "HEART_RATE",
                "RESTING_HEART_RATE",
                "OXYGEN",
                "GLUCOSE",
                "PRESSURE",
            ]
            for table in tables:
                await cursor.execute(f"DROP TABLE IF EXISTS {table};")
        await self.conn.commit()
        self.conn.close()

    async def test_create_steps_table(self):
        """Test the creation of the STEPS table."""
        await create_steps_table(self.conn)
        async with self.conn.cursor() as cursor:
            await cursor.execute("SHOW TABLES LIKE 'STEPS';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, "STEPS table was not created.")

    async def test_create_heartRate_table(self):
        """Test the creation of the HEART_RATE table."""
        await create_heartRate_table(self.conn)
        async with self.conn.cursor() as cursor:
            await cursor.execute("SHOW TABLES LIKE 'HEART_RATE';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, "HEART_RATE table was not created.")

    async def test_create_restingHeartRate_table(self):
        """Test the creation of the RESTING_HEART_RATE table."""
        await create_restingHeartRate_table(self.conn)
        async with self.conn.cursor() as cursor:
            await cursor.execute("SHOW TABLES LIKE 'RESTING_HEART_RATE';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, "RESTING_HEART_RATE table was not created.")

    async def test_create_oxygen_table(self):
        """Test the creation of the OXYGEN table."""
        await create_oxygen_table(self.conn)
        async with self.conn.cursor() as cursor:
            await cursor.execute("SHOW TABLES LIKE 'OXYGEN';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, "OXYGEN table was not created.")

    async def test_create_glucose_table(self):
        """Test the creation of the GLUCOSE table."""
        await create_glucose_table(self.conn)
        async with self.conn.cursor() as cursor:
            await cursor.execute("SHOW TABLES LIKE 'GLUCOSE';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, "GLUCOSE table was not created.")

    async def test_create_pressure_table(self):
        """Test the creation of the PRESSURE table."""
        await create_pressure_table(self.conn)
        async with self.conn.cursor() as cursor:
            await cursor.execute("SHOW TABLES LIKE 'PRESSURE';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, "PRESSURE table was not created.")
