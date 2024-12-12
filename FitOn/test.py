from datetime import datetime
from django.test import TestCase, Client, override_settings, RequestFactory

from django.core.files.uploadedfile import SimpleUploadedFile

from unittest.mock import patch, MagicMock, AsyncMock
from datetime import timedelta
from FitOn import views
import pandas as pd

from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.urls import reverse
import boto3
import json
import uuid

import io
import asyncio
import sys
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
    insert_into_steps_table,
    insert_into_glucose_table,
    insert_into_heartRate_table,
    insert_into_oxygen_table,
    insert_into_pressure_table,
    insert_into_restingHeartRate_table,
    show_table,
    rds_main,
    fetch_user_data,
    table_exists,
    insert_into_tables,
    show_tables,
)
import aiomysql
from FitOn.rds import create_table, insert_data
from unittest import IsolatedAsyncioTestCase

# import unittest

# from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password

# from django.contrib.auth.hashers import check_password

# from django.contrib.sessions.models import Session
# from django.utils import timezone
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core import mail

# from django.conf import settings
from importlib import reload, import_module
from pathlib import Path

# from django.utils import timezone


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
    verify_user_credentials,
    get_users_by_username_query,
    get_sleep_user_goals,
    get_weight_user_goals,
    get_step_user_goals,
    # make_fitness_trainer,
    # remove_fitness_trainer,
    # get_user_by_username,
    calculate_age_group,
    MockUser,
    # users_table,
    get_last_reset_request_time,
    update_reset_request_time,
    save_chat_message,
    get_users_without_specific_username,
    get_chat_history_from_db,
    get_users_with_chat_history,
)
from botocore.exceptions import ClientError, ValidationError
import pytz

# from django.contrib import messages
from django.contrib.messages import get_messages
from .forms import (
    SignUpForm,
    SetNewPasswordForm,
    ProfileForm,
    validate_file_extension,
)
from .views import (
    homepage,
    add_message,
    perform_redirect,
    login,
    custom_logout,
    signup,
    forum_view,
    warn_action,
    dismiss_warning,
    authorize_google_fit,
    callback_google_fit,
    delink_google_fit,
    get_metric_data,
    fetch_all_metric_data,
    format_bod_fitness_data,
    process_dynamo_data,
    parse_millis,
    get_group_key,
    merge_data,
    steps_barplot,
    resting_heartrate_plot,
    activity_plot,
    oxygen_plot,
    glucose_plot,
    pressure_plot,
    fetch_metric_data,
    get_sleep_scores,
    heartrate_plot,
    create_room_id,
    create_group_chat,
)
from django.contrib.auth.hashers import check_password, make_password
from channels.testing import WebsocketCommunicator
from .models import GroupChatMember
from FitOn.asgi import application
from boto3.dynamodb.conditions import Key
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory


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

    def test_verify_false_credentials(self):
        username = "wasd"
        password = "wasd"
        result = verify_user_credentials(username, password)
        self.assertIsNone(result, "User was found. ")

    def test_verify_true_credentials(self):
        username = "sg8002"
        password = "sg8002"
        result = verify_user_credentials(username, password)
        self.assertIsNotNone(result, "Invalid credentials. ")

    def test_get_users_by_username_query(self):
        query = "sg8002"
        results = get_users_by_username_query(query)
        assert len(results) > 0, "Query should return 1 user"

    # def test_make_fitness_trainer(self):
    #     user = get_user_by_username("sg8002")
    #     uid = user.get("user_id")
    #     make_fitness_trainer(uid)

    #     is_FT = user.get("is_fitness_trainer")
    #     self.assertTrue(is_FT, "sg8002 is not a Fitness Trainer")

    #     remove_fitness_trainer(uid)
    #     is_FT = user.get("is_fitness_trainer")
    #     self.assertFalse(is_FT, "sg8002 is still a Fitness Trainer")

    def test_calculate_age_group(self):
        test_cases = [
            ("2015-06-15", "Child"),  # Age: 9
            ("2007-01-01", "Teenager"),  # Age: 17
            ("1995-11-20", "Young Adult"),  # Age: 29
            ("1980-05-10", "Middle-aged"),  # Age: 44
            ("1950-12-25", "Senior"),  # Age: 74
            ("1940-01-01", "Elderly"),  # Age: 84
        ]

        for date_of_birth, expected_group in test_cases:
            result = calculate_age_group(date_of_birth)
            assert (
                result == expected_group
            ), f"Expected {expected_group}, got {result} for DOB {date_of_birth}"

        invalid_cases = [
            ("invalid-date", "Unknown"),  # Invalid date format
            ("", "Unknown"),  # Empty string
            (None, "Unknown"),  # None as input
        ]

        for date_of_birth, expected_group in invalid_cases:
            result = calculate_age_group(date_of_birth)
            assert (
                result == expected_group
            ), f"Expected {expected_group}, got {result} for DOB {date_of_birth}"

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
        # self.assertTrue(
        #     updated_user.get("is_banned") is True,  # Updated assertion
        #     "User should be banned (is_banned should be True).",
        # )

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
        self.client.post(
            "/unban_user/",
            data=json.dumps({"user_id": self.user_data["user_id"]}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        # self.assertEqual(response.status_code, 200)
        # data = response.json()
        # self.assertEqual(
        #     data["message"],
        #     "User has been unbanned",
        #     "Unban message should confirm unban success.",
        # )

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
        # self.assertIn("Item", response, "User was not found in DynamoDB after muting.")
        updated_user = response["Item"]

        # Check if `is_muted` is set to True
        # self.assertTrue(
        #     updated_user.get("is_muted", True),
        #     "User should be banned (is_muted should be True).",
        # )

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
        self.client.post(
            "/unmute_user/",
            data=json.dumps({"user_id": self.user_data["user_id"]}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        # self.assertEqual(response.status_code, 200)
        # data = response.json()
        # #self.assertEqual(
        #     data["message"],
        #     "User has been unmuted",
        #     "Unmute message should confirm unmute success.",
        # #)

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


class WarnActionTest(TestCase):
    def setUp(self):
        # Mock user data
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
            "is_warned": False,
        }
        # Create the user in the database
        create_user(**self.user_data)

        self.factory = RequestFactory()

    def test_warn_user_for_thread(self):
        # Simulate POST request to warn a user for a thread
        data = {
            "action": "warn_thread",
            "thread_id": "thread_123",
            "user_id": self.user_data["username"],
        }
        request = self.factory.post(
            "/warn_action/",
            data=json.dumps(data),
            content_type="application/json",
        )
        response = warn_action(request)

        # Assert response and user's warning status
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.content)["message"],
            "User warned for thread successfully.",
        )
        warned_user = get_user(self.user_data["user_id"])
        self.assertTrue(warned_user.get("is_warned"))

    def test_warn_user_for_comment(self):
        # Simulate POST request to warn a user for a comment
        data = {
            "action": "warn_comment",
            "post_id": "post_123",
            "user_id": self.user_data["username"],
        }
        request = self.factory.post(
            "/warn_action/",
            data=json.dumps(data),
            content_type="application/json",
        )
        response = warn_action(request)

        # Assert response and user's warning status
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.content)["message"],
            "User warned for comment successfully.",
        )
        warned_user = get_user(self.user_data["user_id"])
        self.assertTrue(warned_user.get("is_warned"))

    def test_warn_user_invalid_action(self):
        # Simulate POST request with invalid action
        data = {
            "action": "invalid_action",
            "user_id": self.user_data["username"],
        }
        request = self.factory.post(
            "/warn_action/",
            data=json.dumps(data),
            content_type="application/json",
        )
        response = warn_action(request)

        # Assert response for invalid action
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            json.loads(response.content)["message"], "Invalid action or ID."
        )

    def tearDown(self):
        # Clean up the test user
        delete_user_by_username(self.user_data["username"])


class DismissWarningTest(TestCase):
    def setUp(self):
        # Mock user data
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
            "is_warned": True,
        }
        # Create the user in the database
        create_user(**self.user_data)

        self.factory = RequestFactory()

    def test_dismiss_warning(self):
        # Simulate user session
        request = self.factory.post("/dismiss_warning/")
        request.session = {"user_id": self.user_data["user_id"]}

        # Call the dismiss_warning view
        response = dismiss_warning(request)
        response_data = json.loads(response.content)
        # Assert response and user's warning status
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response_data["message"],
            f"User {self.user_data['user_id']} warning dismissed.",
        )
        updated_user = get_user(self.user_data["user_id"])
        self.assertFalse(updated_user.get("is_warned"))

    def test_dismiss_warning_no_user_id(self):
        # Simulate request without a user ID in the session
        request = self.factory.post("/dismiss_warning/")
        request.session = {}

        # Call the dismiss_warning view
        response = dismiss_warning(request)

        # Assert response for missing user ID
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["message"], "User ID is missing.")

    def tearDown(self):
        # Clean up the test user
        delete_user_by_username(self.user_data["username"])


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


def add_middleware(request):
    """Helper function to add session and message middleware to the request."""
    session_middleware = SessionMiddleware(lambda req: None)
    session_middleware.process_request(request)
    request.session.save()

    message_middleware = MessageMiddleware(lambda req: None)
    message_middleware.process_request(request)


class GoogleFitViewsTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @patch("google_auth_oauthlib.flow.Flow.from_client_config")
    @patch("django.shortcuts.redirect")
    def test_authorize_google_fit_redirects_to_auth_url(
        self, mock_redirect, mock_flow_from_client_config
    ):
        # Mock the Flow object
        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = (
            "https://example.com/auth",
            "state123",
        )
        mock_flow_from_client_config.return_value = mock_flow

        # Create a request with no credentials in session
        request = self.factory.get(reverse("authorize_google_fit"))
        add_middleware(request)
        request.session["google_fit_credentials"] = None

        # Call the view
        authorize_google_fit(request)

        # # Assertions
        # mock_flow_from_client_config.assert_called_once_with(GOOGLEFIT_CLIENT_CONFIG, SCOPES)
        # mock_flow.authorization_url.assert_called_once_with(
        #     access_type="offline", include_granted_scopes="true"
        # )
        # mock_redirect.assert_called_once_with("https://example.com/auth")
        # self.assertIn("google_fit_state", request.session)
        # self.assertEqual(request.session["google_fit_state"], "state123")

    @patch("google_auth_oauthlib.flow.Flow.from_client_config")
    @patch("django.shortcuts.render")
    @patch("FitOn.views.get_user")
    def test_callback_google_fit_success(
        self, mock_get_user, mock_render, mock_flow_from_client_config
    ):
        # Mock the Flow object
        mock_flow = MagicMock()
        mock_flow.fetch_token.return_value = None
        mock_flow.credentials = MagicMock(
            token="test_token",
            refresh_token="test_refresh_token",
            token_uri="test_token_uri",
            client_id="test_client_id",
            client_secret="test_client_secret",
            scopes=["scope1", "scope2"],
        )
        mock_flow_from_client_config.return_value = mock_flow

        # Mock user data
        mock_user = {
            "name": "Test User",
            "date_of_birth": "1990-01-01",
            "email": "test@example.com",
            "gender": "male",
            "phone_number": "1234567890",
            "address": "123 Test Street",
            "bio": "Test bio",
            "country_code": "US",
        }
        mock_get_user.return_value = mock_user

        # Create a request with state in session
        request = self.factory.get(reverse("callback_google_fit"))
        add_middleware(request)
        request.session["google_fit_state"] = "state123"
        request.session["user_id"] = "user123"

        # Call the view
        callback_google_fit(request)

        # # Assertions
        # self.assertIn("credentials", request.session)
        # messages = list(get_messages(request))
        # self.assertTrue(any("Signed in Successfully" in str(m) for m in messages))
        # mock_render.assert_called_once_with(
        #     request,
        #     "profile.html",
        #     {"login_success": True, "form": mock.ANY, "user": mock_user},
        # )

    @patch("google_auth_oauthlib.flow.Flow.from_client_config")
    @patch("django.shortcuts.redirect")
    def test_callback_google_fit_invalid_state(
        self, mock_redirect, mock_flow_from_client_config
    ):
        # Create a request with no state in session
        request = self.factory.get(reverse("callback_google_fit"))
        add_middleware(request)
        request.session["user_id"] = "user123"

        # Call the view
        callback_google_fit(request)

        # # Assertions
        # messages = list(get_messages(request))
        # self.assertTrue(any("Sign-in failed. Please try again." in str(m) for m in messages))
        # mock_redirect.assert_called_once_with(reverse("homepage"))

    @patch("requests.post")
    def test_delink_google_fit_success(self, mock_post):
        # Mock successful revoke response
        mock_post.return_value.status_code = 200

        # Create a request with credentials in the session
        request = self.factory.get(reverse("delink_google_fit"))
        add_middleware(request)
        request.session["credentials"] = {
            "token": "test_token",
            "refresh_token": "test_refresh_token",
            "token_uri": "test_token_uri",
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "scopes": ["scope1", "scope2"],
        }

        # Call the view
        delink_google_fit(request)


###########################################################
#       TEST CASEs FOR PASSWORD RESET              #
###########################################################


class PasswordResetTests(TestCase):
    @classmethod
    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def setUpClass(cls):
        super().setUpClass()
        cls.client = Client()

        # Set up connection to actual DynamoDB tables
        cls.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
        cls.users_table = cls.dynamodb.Table("Users")
        cls.password_reset_table = cls.dynamodb.Table("PasswordResetRequests")

    def setUp(self):
        # Clear outbox for each test
        mail.outbox = []

        # Create a mock user for testing in the actual Users table
        self.mock_user = MockUser(
            {
                "user_id": "mock_user_id",
                "username": "mockuser",
                "email": "mockuser@example.com",
                "password": make_password("mockpassword"),
                "is_active": True,
            }
        )

        # Insert the mock user into the Users table
        self.__class__.users_table.put_item(Item=self.mock_user.__dict__)
        # print("Mock user inserted into DynamoDB for testing.")

    def tearDown(self):
        # Delete the mock user from the Users and PasswordResetRequests tables
        self.__class__.users_table.delete_item(Key={"user_id": self.mock_user.user_id})
        self.__class__.password_reset_table.delete_item(
            Key={"user_id": self.mock_user.user_id}
        )

        # Clear the email outbox after each test
        mail.outbox = []
        super().tearDown()

    @classmethod
    def tearDownClass(cls):
        # Any additional cleanup at the class level can go here
        super().tearDownClass()

    def test_password_reset_request_invalid_email(self):
        # Test with an email that does not exist in the database
        self.client.post(
            reverse("password_reset_request"), {"email": "nonexistent@example.com"}
        )
        print("Testing password reset with a nonexistent email.")

        # Ensure no email was sent
        self.assertEqual(
            len(mail.outbox), 0, "Expected no email to be sent for non-existent email."
        )

    def test_password_reset_request_valid_email(self):
        # Test with the mock user's email
        self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )

        # Ensure an email was sent
        self.assertEqual(len(mail.outbox), 1, "Expected exactly one email to be sent.")
        email = mail.outbox[0]
        self.assertEqual(email.to, [self.mock_user.email])

    def test_password_reset_link_in_email(self):
        # Test if the password reset link is in the email
        self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )
        self.assertEqual(len(mail.outbox), 1, "Expected one email in the outbox")
        email = mail.outbox[0]

        # Check if the email contains a reset link
        self.assertIn("reset your password", email.body.lower())
        print(f"Password reset link sent to: {email.to}")

    def test_password_reset_confirm_with_valid_token(self):
        # Generate a valid token for the mock user
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

        # Test accessing the password reset confirm page with a valid token
        response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Set New Password")

    def test_password_reset_confirm_with_invalid_token(self):
        # Generate an invalid token and test the reset confirm page
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))
        invalid_token = "invalid-token"

        response = self.client.get(
            reverse("password_reset_confirm", args=[uid, invalid_token])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, "The password reset link is invalid or has expired."
        )

    def test_password_reset_mismatched_passwords(self):
        # Generate a valid token
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

        # Post mismatched passwords
        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": "newpassword123", "confirm_password": "wrongpassword"},
        )
        self.assertContains(response, "Passwords do not match.", status_code=200)

    def test_successful_password_reset(self):
        # Generate a valid token and UID
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

        # Successfully reset the password
        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": "newpassword123", "confirm_password": "newpassword123"},
            follow=True,
        )
        self.assertRedirects(response, reverse("password_reset_complete"))

        # Verify new password by attempting to log in
        updated_user = get_user_by_email(self.mock_user.email)
        self.assertTrue(
            updated_user and updated_user.password, "Password reset was not successful."
        )

    def test_password_reset_complete_view(self):
        # Test if the password reset complete page renders correctly
        response = self.client.get(reverse("password_reset_complete"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Your password has been successfully reset.")

    def test_password_reset_throttling(self):
        # First password reset request
        response = self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )
        self.assertEqual(len(mail.outbox), 1, "Expected exactly one email to be sent.")

        # Attempt a second request immediately, which should be throttled
        response = self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )
        self.assertContains(response, "Please wait", status_code=200)
        self.assertEqual(
            len(mail.outbox), 1, "No additional email should be sent due to throttling."
        )

    def test_password_reset_request_case_sensitive_email(self):
        # Enter a valid email with incorrect casing
        self.client.post(
            reverse("password_reset_request"), {"email": "MockUser@example.com"}
        )
        # No email should be sent due to case sensitivity
        self.assertEqual(
            len(mail.outbox),
            0,
            "Expected no email to be sent due to case-sensitive mismatch.",
        )
        print(
            "Tested case-sensitive email matching: no email sent for mismatched case."
        )

    def test_password_reset_request_inactive_user(self):
        self.mock_user.is_active = False
        self.__class__.users_table.put_item(Item=self.mock_user.__dict__)

        response = self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )
        self.assertContains(
            response, "The email you entered is not registered", status_code=200
        )
        self.assertEqual(
            len(mail.outbox), 0, "No email should be sent for an inactive user."
        )

    @patch(
        "django.contrib.auth.tokens.default_token_generator.check_token",
        return_value=False,
    )
    def test_expired_token_password_reset_confirm(self, mock_check_token):
        # Generate a valid token with the current time
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

        # Mock the token check to simulate an expired token
        print("Simulating expired token by forcing check_token to return False.")

        # Attempt to reset password with the "expired" token
        response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            status_code=200,
        )

    def test_password_reset_email_content(self):
        self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )
        self.assertEqual(len(mail.outbox), 1, "Expected one email to be sent.")
        email = mail.outbox[0]

        # Check if email contains specific expected content
        self.assertIn("reset your password", email.body.lower())
        self.assertIn(
            self.mock_user.username, email.body
        )  # Username should be included in the email
        reset_url_fragment = reverse(
            "password_reset_confirm",
            args=[
                urlsafe_base64_encode(force_bytes(self.mock_user.user_id)),
                default_token_generator.make_token(self.mock_user),
            ],
        )
        self.assertIn(reset_url_fragment, email.body)

    def test_login_with_new_password_after_reset(self):
        # Generate a valid token and reset the password
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))
        new_password = "newpassword123"

        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": new_password, "confirm_password": new_password},
            follow=True,
        )
        self.assertRedirects(response, reverse("password_reset_complete"))

        # Now attempt to log in with the new password
        response = self.client.post(
            reverse("login"),
            {"username": self.mock_user.username, "password": new_password},
        )
        self.assertRedirects(response, reverse("homepage"))

    def test_password_reset_confirm_invalid_uid(self):
        # Generate a valid token but use an invalid UID
        invalid_uid = "invalid-uid"
        token = default_token_generator.make_token(self.mock_user)

        response = self.client.get(
            reverse("password_reset_confirm", args=[invalid_uid, token])
        )
        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            status_code=200,
        )

    def test_single_use_token(self):
        # Generate a valid token and UID
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

        # First reset attempt with valid token
        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": "newpassword123", "confirm_password": "newpassword123"},
        )
        self.assertRedirects(response, reverse("password_reset_complete"))

        # Second reset attempt with the same token should fail
        response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            status_code=200,
        )

    def test_password_reset_request_with_html_injection(self):
        response = self.client.post(
            reverse("password_reset_request"),
            {"email": "<script>alert('xss')</script>@example.com"},
        )
        self.assertContains(response, "Enter a valid email address.", status_code=200)
        self.assertEqual(
            len(mail.outbox),
            0,
            "No email should be sent for an invalid email with HTML.",
        )

    def test_password_reset_confirm_access_without_token(self):
        response = self.client.get(
            reverse("password_reset_confirm", args=["invalid-uid", "invalid-token"])
        )
        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            status_code=200,
        )

    def test_password_reset_request_template(self):
        response = self.client.get(reverse("password_reset_request"))
        self.assertTemplateUsed(response, "password_reset_request.html")
        self.assertContains(response, "Reset Password")

    def test_password_reset_confirm_template(self):
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))
        response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
        self.assertTemplateUsed(response, "password_reset_confirm.html")
        self.assertContains(response, "Set New Password")

    def test_password_reset_request_with_malformed_email(self):
        # Test with a malformed email address
        response = self.client.post(
            reverse("password_reset_request"),
            {"email": "user@.com"},
        )
        self.assertContains(response, "Enter a valid email address.", status_code=200)
        self.assertEqual(
            len(mail.outbox),
            0,
            "No email should be sent for a malformed email address.",
        )

    def test_password_reset_accessibility_without_login(self):
        # Access the password reset request page
        response = self.client.get(reverse("password_reset_request"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Reset Password")

        # Generate valid token and UID
        token = default_token_generator.make_token(self.mock_user)
        uid = urlsafe_base64_encode(force_bytes(self.mock_user.user_id))

        # Access the password reset confirmation page with a valid token
        response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Set New Password")

    def test_password_reset_request_with_injection_attempt(self):
        injection_email = "user@example.com'; DROP TABLE Users; --"
        response = self.client.post(
            reverse("password_reset_request"), {"email": injection_email}
        )
        self.assertEqual(
            len(mail.outbox), 0, "No email should be sent for an injection attempt."
        )
        self.assertContains(response, "Enter a valid email address.", status_code=200)

    def test_get_last_reset_request_time_existing_item(self):
        # Insert a mock item into the password reset table
        self.__class__.password_reset_table.put_item(
            Item={
                "user_id": self.mock_user.user_id,
                "last_request_time": "2024-12-03T00:00:00Z",
            }
        )

        # Call the function and verify it retrieves the correct time
        last_request_time = get_last_reset_request_time(self.mock_user.user_id)
        self.assertEqual(
            last_request_time,
            "2024-12-03T00:00:00Z",
            "The function did not return the expected last reset request time.",
        )

        # Clean up after the test
        self.__class__.password_reset_table.delete_item(
            Key={"user_id": self.mock_user.user_id}
        )

    def test_get_last_reset_request_time_missing_item(self):
        # Ensure the user_id does not exist in the password reset table
        self.__class__.password_reset_table.delete_item(
            Key={"user_id": self.mock_user.user_id}
        )

        # Call the function and verify it returns None
        last_request_time = get_last_reset_request_time(self.mock_user.user_id)
        self.assertIsNone(
            last_request_time,
            "The function should return None when the item does not exist.",
        )

    @patch("FitOn.dynamodb.password_reset_table.get_item")
    def test_get_last_reset_request_time_handles_exception(self, mock_get_item):
        # Simulate an exception when `get_item` is called
        mock_get_item.side_effect = Exception("Simulated DynamoDB error")

        # Call the function and verify it handles the exception gracefully
        with self.assertRaises(Exception):
            get_last_reset_request_time(self.mock_user.user_id)

    def test_update_reset_request_time_new_entry(self):
        # Call the function to insert a new reset request time
        update_reset_request_time(self.mock_user.user_id)

        # Verify the item was created in the table
        response = self.__class__.password_reset_table.get_item(
            Key={"user_id": self.mock_user.user_id}
        )
        self.assertIn("Item", response, "Expected the item to be created in the table.")
        self.assertIn(
            "last_request_time",
            response["Item"],
            "Expected the 'last_request_time' field to exist in the item.",
        )

    def test_update_reset_request_time_update_existing_entry(self):
        # Insert an existing entry
        self.__class__.password_reset_table.put_item(
            Item={
                "user_id": self.mock_user.user_id,
                "last_request_time": "2024-12-01T10:00:00Z",
            }
        )

        # Call the function to update the reset request time
        update_reset_request_time(self.mock_user.user_id)

        # Verify the item was updated in the table
        response = self.__class__.password_reset_table.get_item(
            Key={"user_id": self.mock_user.user_id}
        )
        self.assertIn("Item", response, "Expected the item to exist in the table.")
        updated_time = response["Item"].get("last_request_time")
        self.assertIsNotNone(
            updated_time, "Expected 'last_request_time' to be updated."
        )
        self.assertNotEqual(
            updated_time,
            "2024-12-01T10:00:00Z",
            "Expected 'last_request_time' to be updated to a new value.",
        )

    def test_update_reset_request_time_invalid_user_id(self):
        # Call the function with an invalid user ID
        with self.assertRaises(Exception):
            update_reset_request_time(None)

    @patch("FitOn.dynamodb.password_reset_table.put_item")
    def test_update_reset_request_time_handles_exception(self, mock_put_item):
        # Simulate an exception when `put_item` is called
        mock_put_item.side_effect = Exception("Simulated DynamoDB error")

        # Call the function and ensure it raises an exception
        with self.assertRaises(Exception):
            update_reset_request_time(self.mock_user.user_id)

    def test_update_reset_request_time_datetime_format(self):
        # Call the function to insert a new reset request time
        update_reset_request_time(self.mock_user.user_id)

        # Verify the datetime format in the table
        response = self.__class__.password_reset_table.get_item(
            Key={"user_id": self.mock_user.user_id}
        )
        self.assertIn("Item", response, "Expected the item to be created in the table.")
        last_request_time = response["Item"].get("last_request_time")
        self.assertIsNotNone(
            last_request_time, "Expected 'last_request_time' to be present."
        )

        # Verify the format of the datetime string
        datetime.fromisoformat(last_request_time)

    def test_password_reset_request_missing_email(self):
        # Make a POST request without providing an email
        response = self.client.post(reverse("password_reset_request"), {"email": ""})

        # Verify the form-specific error message for empty email
        self.assertContains(
            response,
            "This field is required.",
            status_code=200,
            msg_prefix="Expected a form error when email is not provided.",
        )

        # Verify that the rendered template is correct
        self.assertTemplateUsed(response, "password_reset_request.html")

        # Verify that no email is sent
        self.assertEqual(
            len(mail.outbox), 0, "No email should be sent when no email is provided."
        )

    def test_password_reset_done_view(self):
        # Make a GET request to the password_reset_done URL
        response = self.client.get(reverse("password_reset_done"))

        # Verify the response status code
        self.assertEqual(
            response.status_code,
            200,
            "Expected status code 200 when accessing the password reset done page.",
        )

        # Verify that the correct template is used
        self.assertTemplateUsed(
            response,
            "password_reset_done.html",
            "Expected the password_reset_done.html template to be rendered.",
        )

        # Verify that the response contains the correct heading
        self.assertContains(
            response,
            "Password Reset Email Sent",
            msg_prefix="Expected the heading 'Password Reset Email Sent' on the password reset done page.",
        )

        # Verify that the response contains the correct paragraph
        self.assertContains(
            response,
            "Please check your email for a link to reset your password.",
            msg_prefix="Expected the message 'Please check your email for a link to reset your password.' on the password reset done page.",
        )

    def test_password_reset_confirm_mismatched_passwords(self):
        # Generate a valid token and UID
        user_id = self.mock_user.user_id
        token = default_token_generator.make_token(self.mock_user)
        uidb64 = urlsafe_base64_encode(force_bytes(user_id))

        # Post mismatched passwords to the password reset confirm view
        response = self.client.post(
            reverse(
                "password_reset_confirm", kwargs={"uidb64": uidb64, "token": token}
            ),
            {
                "new_password": "newpassword123",
                "confirm_password": "differentpassword456",
            },
        )

        # Verify that the response contains the form error
        self.assertContains(
            response,
            "Passwords do not match.",
            status_code=200,
            msg_prefix="Expected an error message when passwords do not match.",
        )

        # Verify that the correct template is used
        self.assertTemplateUsed(response, "password_reset_confirm.html")

        # Verify that the password is not updated (since it's a mock object, check manually)
        mock_user_data = self.__class__.users_table.get_item(Key={"user_id": user_id})
        self.assertIn(
            "Item",
            mock_user_data,
            "Expected the mock user to still exist in the database.",
        )
        stored_password = mock_user_data["Item"].get("password")
        self.assertNotEqual(
            stored_password,
            "newpassword123",
            "Password should not be updated when passwords do not match.",
        )

    def test_password_reset_confirm_invalid_uid_or_token(self):
        # Simulate an invalid uidb64 and token
        invalid_uidb64 = "invalid-uid"
        invalid_token = "invalid-token"

        # Make a GET request to the password_reset_confirm view with invalid data
        response = self.client.get(
            reverse(
                "password_reset_confirm",
                kwargs={"uidb64": invalid_uidb64, "token": invalid_token},
            )
        )

        # Verify the status code
        self.assertEqual(
            response.status_code,
            200,
            "Expected status code 200 when accessing with an invalid UID or token.",
        )

        # Verify the correct template is used
        self.assertTemplateUsed(response, "password_reset_invalid.html")

        # Verify that the error message is displayed in the response
        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            msg_prefix="Expected an error message when UID or token is invalid.",
        )

        # Verify that the HTML structure matches the invalid page
        self.assertContains(
            response,
            "<h2>Password Reset Error</h2>",
            msg_prefix="Expected the heading 'Password Reset Error' on the invalid password reset page.",
        )


class EmailBackendTests(TestCase):
    def test_testing_flag_true_uses_locmem_backend(self):
        # Mock sys.argv to simulate a testing environment
        with patch("sys.argv", new=["manage.py", "test"]):
            settings = import_module("FitOn.settings")
            reload(settings)  # Reload the module to apply changes

            # Check that the testing email backend is applied
            self.assertEqual(
                settings.EMAIL_BACKEND,
                "django.core.mail.backends.locmem.EmailBackend",
                "Expected locmem email backend in testing mode.",
            )

    def test_testing_flag_false_uses_smtp_backend(self):
        # Mock sys.argv to simulate a production-like environment
        with patch("sys.argv", new=["manage.py", "runserver"]):
            settings = import_module("FitOn.settings")
            reload(settings)  # Reload the module to apply changes

            # Check that the production SMTP email backend is applied
            self.assertEqual(
                settings.EMAIL_BACKEND,
                "django.core.mail.backends.smtp.EmailBackend",
                "Expected SMTP email backend in production mode.",
            )
            self.assertEqual(
                settings.EMAIL_HOST, "smtp.gmail.com", "EMAIL_HOST is incorrect."
            )
            self.assertEqual(settings.EMAIL_PORT, 587, "EMAIL_PORT is incorrect.")
            self.assertTrue(settings.EMAIL_USE_TLS, "EMAIL_USE_TLS should be True.")
            self.assertEqual(
                settings.EMAIL_HOST_USER,
                "fiton.notifications@gmail.com",
                "EMAIL_HOST_USER is incorrect.",
            )
            self.assertEqual(
                settings.EMAIL_HOST_PASSWORD,
                "usfb imrp rhyq npif",
                "EMAIL_HOST_PASSWORD is incorrect.",
            )


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

        homepage(request)
        # self.assertEqual(response.status_code, 200)
        # self.assertContains(
        #     response, "sg8002"
        # )  # Check that "JohnDoe" is in the response content

    def test_homepage_without_username(self):
        request = self.factory.get("/")
        request.session = {}  # No username in the session

        homepage(request)
        # self.assertEqual(response.status_code, 200)
        # self.assertContains(
        # response, "Guest"
        # )  # Check that "Guest" is in the response content


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


class FitnessGoalsViewTest(TestCase):
    def setUp(self):
        # Set up DynamoDB resource and table
        self.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
        self.goals_table = self.dynamodb.Table("UserGoals")

        # Create test user with updated username
        hashed = make_password("secure_password")
        create_user(
            "test_user789",  # user_id
            "test_user789",  # username
            "test_user789@example.com",  # email
            "Test User 789",  # name
            "1990-01-01",  # date_of_birth
            "O",  # gender
            "183",  # height
            "83",  # weight
            hashed,  # plaintext password
        )

        # Set user_id for the test session
        self.user_id = "test_user789"

        # Simulate a login request to your login view
        self.client = Client()
        response = self.client.post(
            "/login/",
            {
                "username": "test_user789",
                "password": "secure_password",
            },
        )

        # Assert that login succeeded
        assert (
            response.status_code == 302
        ), "Login request did not redirect as expected."

        # Confirm session setup
        session = self.client.session
        assert "user_id" in session, "User ID not found in session after login."
        assert (
            session["user_id"] == self.user_id
        ), "Session user_id does not match the test user."

    def test_view_renders_goals_page(self):
        response = self.client.get("/fitness-goals/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "fitness_goals.html")

    def test_add_new_goal(self):
        # Ensure the session is properly set up
        self.assertIn("user_id", self.client.session, "User ID not found in session.")
        self.assertEqual(
            self.client.session["user_id"], self.user_id, "Session user_id mismatch."
        )

        # Test adding a new goal
        data = {
            "goal_type": "steps",
            "goal_name": "",
            "goal_value": "10000",
        }

        data2 = {
            "goal_type": "weight",
            "goal_name": "",
            "goal_value": "80",
        }
        response = self.client.post("/fitness-goals/", data)
        response = self.client.post("/fitness-goals/", data2)

        # Assert redirect
        self.assertEqual(response.status_code, 302, "Expected redirect status code.")
        self.assertEqual(
            response.url, reverse("fitness_goals"), "Redirect URL mismatch."
        )

        steps = get_step_user_goals(self.user_id)
        self.assertEqual(steps, "10000", f"Expected goal value '10000', got {steps}.")

        weight = get_weight_user_goals(self.user_id)
        self.assertEqual(weight, "80", f"Expected goal value '80', got {weight}.")

    def test_prevent_duplicate_goal_type(self):
        # Insert an initial goal
        initial_goal = {
            "GoalID": str(uuid.uuid4()),
            "user_id": self.user_id,
            "Type": "steps",
            "Name": None,
            "Value": "10000",
        }
        self.goals_table.put_item(Item=initial_goal)

        # Validate the initial state
        query_response = self.goals_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("user_id").eq(
                self.user_id
            )
        )
        initial_goals = query_response.get("Items", [])
        self.assertGreater(
            len(initial_goals), 0, "Initial goal was not added to DynamoDB."
        )

        # Attempt to add a duplicate goal
        data = {
            "goal_type": "steps",
            "goal_name": "",
            "goal_value": "15000",
        }
        response = self.client.post("/fitness-goals/", data)

        # Assert redirect
        self.assertEqual(response.status_code, 302, "Expected redirect status code.")
        self.assertEqual(
            response.url, reverse("fitness_goals"), "Redirected to an incorrect URL."
        )

        # Check for error message in session messages
        messages = list(response.wsgi_request._messages)
        self.assertEqual(len(messages), 1, "Expected one error message in session.")
        self.assertEqual(
            str(messages[0]),
            "You already have a steps goal. Please edit it instead.",
            "Error message mismatch for duplicate goal prevention.",
        )

    def test_fetch_goals_on_get(self):
        # Insert a sample goal
        sample_goal = {
            "GoalID": str(uuid.uuid4()),
            "user_id": self.user_id,
            "Type": "sleep",
            "Name": None,
            "Value": "10",
        }
        self.goals_table.put_item(Item=sample_goal)

        # Validate the initial state
        query_response = self.goals_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("user_id").eq(
                self.user_id
            )
        )
        goals = query_response.get("Items", [])
        self.assertGreater(len(goals), 0, "Initial goal was not added to DynamoDB.")

        # Fetch goals via GET request
        response = self.client.get(reverse("fitness_goals"))
        self.assertEqual(
            response.status_code, 200, "GET request to fetch goals failed."
        )

        # Check if the inserted goal is displayed
        response_content = str(response.content)
        self.assertIn(
            "sleep",
            response_content,
            "Goal type 'sleep' not found in response content.",
        )
        self.assertIn(
            "10", response_content, "Goal value '10' not found in response content."
        )

    def test_edit_goal(self):
        # Insert an initial goal
        initial_goal = {
            "GoalID": str(uuid.uuid4()),
            "user_id": self.user_id,
            "Type": "sleep",
            "Name": None,
            "Value": "8",
        }
        self.goals_table.put_item(Item=initial_goal)

        # Validate the initial state
        sleep = get_sleep_user_goals(self.user_id)
        self.assertEqual(sleep, "8", "Initial goal value mismatch.")

        # Data for editing the goal
        edit_data = {
            "goal_id": initial_goal["GoalID"],
            "goal_value": "5",
        }

        # Make POST request to edit the goal
        response = self.client.post(
            reverse("edit_goal"),
            data=json.dumps(edit_data),
            content_type="application/json",
        )

        # Assert the response
        self.assertEqual(response.status_code, 200, "Goal edit request failed.")
        self.assertEqual(
            response.json()["message"],
            "Goal updated successfully!",
            "Success message mismatch.",
        )

        # Validate the updated goal in DynamoDB
        updated_goal_response = self.goals_table.get_item(
            Key={
                "GoalID": initial_goal["GoalID"],
                "user_id": self.user_id,
            }
        )
        updated_goal = updated_goal_response.get("Item")
        self.assertIsNotNone(updated_goal, "Updated goal not found in DynamoDB.")
        self.assertEqual(
            updated_goal["Value"],
            "5",
            f"Expected updated value '5', got {updated_goal['Value']}.",
        )

        # --- Delete the updated goal ---
        delete_data = {
            "goal_id": initial_goal["GoalID"],
        }

        # Make POST request to delete the goal
        response = self.client.post(
            reverse("delete_goal"),
            data=json.dumps(delete_data),
            content_type="application/json",
        )

        # Assert the deletion response
        self.assertEqual(response.status_code, 200, "Goal delete request failed.")
        self.assertEqual(
            response.json()["message"],
            "Goal deleted successfully.",
            "Unexpected response message for goal deletion.",
        )

        # Validate the goal is deleted
        deleted_goal_response = self.goals_table.get_item(
            Key={
                "GoalID": initial_goal["GoalID"],
                "user_id": self.user_id,
            }
        )
        deleted_goal = deleted_goal_response.get("Item")
        self.assertIsNone(deleted_goal, "Deleted goal still found in DynamoDB.")

    def tearDown(self):
        response = self.goals_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("user_id").eq(
                self.user_id
            )
        )
        goals = response.get("Items", [])

        # Delete each goal
        for goal in goals:
            self.goals_table.delete_item(
                Key={
                    "GoalID": goal["GoalID"],
                    "user_id": self.user_id,
                }
            )


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
        """Clean up test case entries after each test."""
        async with self.conn.cursor() as cursor:
            # Drop only test-specific tables
            tables = [
                "test_steps",
                "test_heart_rate",
                "test_resting_heart_rate",
                "test_oxygen",
                "test_glucose",
                "test_pressure",
            ]
            for table in tables:
                await cursor.execute(f"DROP TABLE IF EXISTS {table};")
        await self.conn.commit()
        self.conn.close()

    async def test_create_steps_table(self):
        """Test the creation of the STEPS table."""
        table_name = "test_steps"  # Use a test-specific table name
        await create_steps_table(self.conn, table_name)
        async with self.conn.cursor() as cursor:
            await cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, f"Table {table_name} was not created.")

    async def test_create_heartRate_table(self):
        """Test the creation of the HEART_RATE table."""
        table_name = "test_heart_rate"
        await create_heartRate_table(self.conn, table_name)
        async with self.conn.cursor() as cursor:
            await cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, f"Table {table_name} was not created.")

    async def test_create_restingHeartRate_table(self):
        """Test the creation of the RESTING_HEART_RATE table."""
        table_name = "test_resting_heart_rate"
        await create_restingHeartRate_table(self.conn, table_name)
        async with self.conn.cursor() as cursor:
            await cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, f"Table {table_name} was not created.")

    async def test_create_oxygen_table(self):
        """Test the creation of the OXYGEN table."""
        table_name = "test_oxygen"
        await create_oxygen_table(self.conn, table_name)
        async with self.conn.cursor() as cursor:
            await cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, f"Table {table_name} was not created.")

    async def test_create_glucose_table(self):
        """Test the creation of the GLUCOSE table."""
        table_name = "test_glucose"
        await create_glucose_table(self.conn, table_name)
        async with self.conn.cursor() as cursor:
            await cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, f"Table {table_name} was not created.")

    async def test_create_pressure_table(self):
        """Test the creation of the PRESSURE table."""
        table_name = "test_pressure"
        await create_pressure_table(self.conn, table_name)
        async with self.conn.cursor() as cursor:
            await cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = await cursor.fetchone()
        self.assertIsNotNone(result, f"Table {table_name} was not created.")


class TestInsertIntoMetricTables(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up a database connection before each test."""
        self.conn = await create_connection()

    async def asyncTearDown(self):
        """Clean up database connection after each test."""
        async with self.conn.cursor() as cursor:
            # Drop test-specific tables
            tables = [
                "test_steps",
                "test_heart_rate",
                "test_resting_heart_rate",
                "test_oxygen",
                "test_glucose",
                "test_pressure",
            ]
            for table in tables:
                await cursor.execute(f"DROP TABLE IF EXISTS {table};")
        await self.conn.commit()
        self.conn.close()

    async def test_insert_into_steps_table(self):
        """Test inserting data into the test-specific STEPS table."""
        table_name = "test_steps"
        await create_steps_table(self.conn, table_name)

        email = "test_user2@example.com"
        start_time = "Dec 03, 9 AM"
        end_time = "Dec 03, 10 AM"
        count = 1000

        await insert_into_steps_table(
            self.conn, email, start_time, end_time, count, table_name
        )

        async with self.conn.cursor() as cursor:
            await cursor.execute(
                f"SELECT * FROM {table_name} WHERE email = %s;", (email,)
            )
            result = await cursor.fetchone()

        self.assertIsNotNone(result, f"Data was not inserted into {table_name} table.")
        self.assertEqual(result[0], email, "Email does not match.")
        self.assertEqual(result[3], count, "Step count does not match.")

    async def test_insert_into_heartRate_table(self):
        """Test inserting data into the test-specific HEART_RATE table."""
        table_name = "test_heart_rate"
        await create_heartRate_table(self.conn, table_name)

        email = "test_user@example.com"
        start_time = "Dec 03, 9 AM"
        end_time = "Dec 03, 10 AM"
        count = 80

        await insert_into_heartRate_table(
            self.conn, email, start_time, end_time, count, table_name
        )

        async with self.conn.cursor() as cursor:
            await cursor.execute(
                f"SELECT * FROM {table_name} WHERE email = %s;", (email,)
            )
            result = await cursor.fetchone()

        self.assertIsNotNone(result, f"Data was not inserted into {table_name} table.")
        self.assertEqual(result[0], email, "Email does not match.")
        self.assertEqual(result[3], count, "Heart rate count does not match.")

    async def test_insert_into_restingHeartRate_table(self):
        """Test inserting data into the test-specific RESTING_HEART_RATE table."""
        table_name = "test_resting_heart_rate"
        await create_restingHeartRate_table(self.conn, table_name)

        email = "test_user@example.com"
        start_time = "Dec 03, 9 AM"
        end_time = "Dec 03, 10 AM"
        count = 60

        await insert_into_restingHeartRate_table(
            self.conn, email, start_time, end_time, count, table_name
        )

        async with self.conn.cursor() as cursor:
            await cursor.execute(
                f"SELECT * FROM {table_name} WHERE email = %s;", (email,)
            )
            result = await cursor.fetchone()

        self.assertIsNotNone(result, f"Data was not inserted into {table_name} table.")
        self.assertEqual(result[0], email, "Email does not match.")
        self.assertEqual(result[3], count, "Resting heart rate count does not match.")

    async def test_insert_into_oxygen_table(self):
        """Test inserting data into the test-specific OXYGEN table."""
        table_name = "test_oxygen"
        await create_oxygen_table(self.conn, table_name)

        email = "test_user@example.com"
        start_time = "Dec 03, 9 AM"
        end_time = "Dec 03, 10 AM"
        count = 95

        await insert_into_oxygen_table(
            self.conn, email, start_time, end_time, count, table_name
        )

        async with self.conn.cursor() as cursor:
            await cursor.execute(
                f"SELECT * FROM {table_name} WHERE email = %s;", (email,)
            )
            result = await cursor.fetchone()

        self.assertIsNotNone(result, f"Data was not inserted into {table_name} table.")
        self.assertEqual(result[0], email, "Email does not match.")
        self.assertEqual(result[3], count, "Oxygen level count does not match.")

    async def test_insert_into_glucose_table(self):
        """Test inserting data into the test-specific GLUCOSE table."""
        table_name = "test_glucose"
        await create_glucose_table(self.conn, table_name)

        email = "test_user@example.com"
        start_time = "Dec 03, 9 AM"
        end_time = "Dec 03, 10 AM"
        count = 120

        await insert_into_glucose_table(
            self.conn, email, start_time, end_time, count, table_name
        )

        async with self.conn.cursor() as cursor:
            await cursor.execute(
                f"SELECT * FROM {table_name} WHERE email = %s;", (email,)
            )
            result = await cursor.fetchone()

        self.assertIsNotNone(result, f"Data was not inserted into {table_name} table.")
        self.assertEqual(result[0], email, "Email does not match.")
        self.assertEqual(result[3], count, "Glucose level count does not match.")

    async def test_insert_into_pressure_table(self):
        """Test inserting data into the test-specific PRESSURE table."""
        table_name = "test_pressure"
        await create_pressure_table(self.conn, table_name)

        email = "test_user@example.com"
        start_time = "Dec 03, 9 AM"
        end_time = "Dec 03, 10 AM"
        count = 120

        await insert_into_pressure_table(
            self.conn, email, start_time, end_time, count, table_name
        )

        async with self.conn.cursor() as cursor:
            await cursor.execute(
                f"SELECT * FROM {table_name} WHERE email = %s;", (email,)
            )
            result = await cursor.fetchone()

        self.assertIsNotNone(result, f"Data was not inserted into {table_name} table.")
        self.assertEqual(result[0], email, "Email does not match.")
        self.assertEqual(result[3], count, "Pressure count does not match.")


class TestInsertIntoAllTables(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up a database connection before each test."""
        self.conn = await create_connection()

    async def asyncTearDown(self):
        """Clean up database connection after each test."""
        async with self.conn.cursor() as cursor:
            # Drop test-specific tables
            tables = [
                "test_steps",
                "test_heart_rate",
                "test_resting_heart_rate",
                "test_oxygen",
                "test_glucose",
                "test_pressure",
            ]
            for table in tables:
                await cursor.execute(f"DROP TABLE IF EXISTS {table};")
        await self.conn.commit()
        self.conn.close()

    async def test_insert_into_tables(self):
        """Test the main function for inserting data into all tables."""
        email = "test_user@example.com"

        # Test data to insert into tables
        total_data = {
            "steps": {
                "2024-12-03": [
                    {"start": "Dec 03, 9 AM", "end": "Dec 03, 10 AM", "count": 1000}
                ]
            },
            "heartRate": {
                "2024-12-03": [
                    {"start": "Dec 03, 10 AM", "end": "Dec 03, 11 AM", "count": 80}
                ]
            },
            "restingHeartRate": {
                "2024-12-03": [
                    {"start": "Dec 03, 9 AM", "end": "Dec 03, 10 AM", "count": 60}
                ]
            },
            "oxygen": {
                "2024-12-03": [
                    {"start": "Dec 03, 9 AM", "end": "Dec 03, 10 AM", "count": 95}
                ]
            },
            "glucose": {
                "2024-12-03": [
                    {"start": "Dec 03, 9 AM", "end": "Dec 03, 10 AM", "count": 120}
                ]
            },
            "pressure": {
                "2024-12-03": [
                    {"start": "Dec 03, 9 AM", "end": "Dec 03, 10 AM", "count": 120}
                ]
            },
        }

        # Test-specific table names
        table_names = {
            "steps": "test_steps",
            "heartRate": "test_heart_rate",
            "restingHeartRate": "test_resting_heart_rate",
            "oxygen": "test_oxygen",
            "glucose": "test_glucose",
            "pressure": "test_pressure",
        }

        # Create test-specific tables
        await create_steps_table(self.conn, table_names["steps"])
        await create_heartRate_table(self.conn, table_names["heartRate"])
        await create_restingHeartRate_table(self.conn, table_names["restingHeartRate"])
        await create_oxygen_table(self.conn, table_names["oxygen"])
        await create_glucose_table(self.conn, table_names["glucose"])
        await create_pressure_table(self.conn, table_names["pressure"])

        # Call the original function with test-specific table names
        await insert_into_tables(email, total_data, table_names)

        # Verify data was inserted into all test-specific tables
        async with self.conn.cursor() as cursor:
            # Check STEPS table
            await cursor.execute(
                f"SELECT * FROM {table_names['steps']} WHERE email = %s;", (email,)
            )
            steps_result = await cursor.fetchone()
            self.assertIsNotNone(
                steps_result, "Data was not inserted into test_steps table."
            )
            self.assertEqual(steps_result[3], 1000, "Step count does not match.")

            # Check HEART_RATE table
            await cursor.execute(
                f"SELECT * FROM {table_names['heartRate']} WHERE email = %s;", (email,)
            )
            heart_rate_result = await cursor.fetchone()
            self.assertIsNotNone(
                heart_rate_result, "Data was not inserted into test_heart_rate table."
            )
            self.assertEqual(
                heart_rate_result[3], 80, "Heart rate count does not match."
            )

            # Check RESTING_HEART_RATE table
            await cursor.execute(
                f"SELECT * FROM {table_names['restingHeartRate']} WHERE email = %s;",
                (email,),
            )
            resting_heart_rate_result = await cursor.fetchone()
            self.assertIsNotNone(
                resting_heart_rate_result,
                "Data was not inserted into test_resting_heart_rate table.",
            )
            self.assertEqual(
                resting_heart_rate_result[3],
                60,
                "Resting heart rate count does not match.",
            )

            # Check OXYGEN table
            await cursor.execute(
                f"SELECT * FROM {table_names['oxygen']} WHERE email = %s;", (email,)
            )
            oxygen_result = await cursor.fetchone()
            self.assertIsNotNone(
                oxygen_result, "Data was not inserted into test_oxygen table."
            )
            self.assertEqual(oxygen_result[3], 95, "Oxygen count does not match.")

            # Check GLUCOSE table
            await cursor.execute(
                f"SELECT * FROM {table_names['glucose']} WHERE email = %s;", (email,)
            )
            glucose_result = await cursor.fetchone()
            self.assertIsNotNone(
                glucose_result, "Data was not inserted into test_glucose table."
            )
            self.assertEqual(glucose_result[3], 120, "Glucose count does not match.")

            # Check PRESSURE table
            await cursor.execute(
                f"SELECT * FROM {table_names['pressure']} WHERE email = %s;", (email,)
            )
            pressure_result = await cursor.fetchone()
            self.assertIsNotNone(
                pressure_result, "Data was not inserted into test_pressure table."
            )
            self.assertEqual(pressure_result[3], 120, "Pressure count does not match.")


class TestShowTable(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up a database connection before each test."""
        self.conn = await create_connection()

    async def asyncTearDown(self):
        """Clean up database connection after each test."""
        async with self.conn.cursor() as cursor:
            # Drop test-specific tables
            tables = ["test_display"]
            for table in tables:
                await cursor.execute(f"DROP TABLE IF EXISTS {table};")
        await self.conn.commit()
        self.conn.close()

    async def test_show_table(self):
        """Test the show_table function to display data."""
        table_name = "test_display"

        # Create a test table
        create_table_query = f"""
        CREATE TABLE {table_name} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            age INT NOT NULL
        );
        """
        async with self.conn.cursor() as cursor:
            await cursor.execute(create_table_query)

        # Insert test data into the table
        test_data = [("Alice", 30), ("Bob", 25), ("Charlie", 35)]
        insert_query = f"INSERT INTO {table_name} (name, age) VALUES (%s, %s)"
        async with self.conn.cursor() as cursor:
            await cursor.executemany(insert_query, test_data)

        await self.conn.commit()

        # Call the show_table function
        async with self.conn.cursor() as cursor:
            await cursor.execute(f"SELECT * FROM {table_name}")
            rows = await cursor.fetchall()

        # Assertions to verify the data is displayed correctly
        self.assertEqual(len(rows), 3, f"Expected 3 rows, but got {len(rows)}.")
        self.assertEqual(rows[0][1], "Alice", "First row name does not match.")
        self.assertEqual(rows[1][1], "Bob", "Second row name does not match.")
        self.assertEqual(rows[2][1], "Charlie", "Third row name does not match.")


class TestShowTableWrappers(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up a database connection before each test."""
        self.conn = await create_connection()

    async def asyncTearDown(self):
        """Clean up database connection after each test."""
        async with self.conn.cursor() as cursor:
            # Drop test-specific tables
            tables = [
                "test_steps",
                "test_heart_rate",
                "test_resting_heart_rate",
                "test_oxygen",
                "test_glucose",
                "test_pressure",
            ]
            for table in tables:
                await cursor.execute(f"DROP TABLE IF EXISTS {table};")
        await self.conn.commit()
        self.conn.close()

    async def test_show_steps_table(self):
        """Test showing data from the test-specific STEPS table."""
        table_name = "test_steps"
        await create_steps_table(self.conn, table_name)

        # Insert test data
        test_data = [
            (
                "test_user@example.com",
                "2024-12-03 09:00:00",
                "2024-12-03 10:00:00",
                1000,
            )
        ]
        insert_query = f"INSERT INTO {table_name} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s)"
        async with self.conn.cursor() as cursor:
            await cursor.executemany(insert_query, test_data)
        await self.conn.commit()

        # Call the wrapper function
        await show_table(self.conn, table_name)

    async def test_show_heartRate_table(self):
        """Test showing data from the test-specific HEART_RATE table."""
        table_name = "test_heart_rate"
        await create_heartRate_table(self.conn, table_name)

        # Insert test data
        test_data = [
            ("test_user@example.com", "2024-12-03 10:00:00", "2024-12-03 11:00:00", 80)
        ]
        insert_query = f"INSERT INTO {table_name} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s)"
        async with self.conn.cursor() as cursor:
            await cursor.executemany(insert_query, test_data)
        await self.conn.commit()

        # Call the wrapper function
        await show_table(self.conn, table_name)

    async def test_show_restingHeartRate_table(self):
        """Test showing data from the test-specific RESTING_HEART_RATE table."""
        table_name = "test_resting_heart_rate"
        await create_restingHeartRate_table(self.conn, table_name)

        # Insert test data
        test_data = [
            ("test_user@example.com", "2024-12-03 09:00:00", "2024-12-03 10:00:00", 60)
        ]
        insert_query = f"INSERT INTO {table_name} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s)"
        async with self.conn.cursor() as cursor:
            await cursor.executemany(insert_query, test_data)
        await self.conn.commit()

        # Call the wrapper function
        await show_table(self.conn, table_name)

    async def test_show_oxygen_table(self):
        """Test showing data from the test-specific OXYGEN table."""
        table_name = "test_oxygen"
        await create_oxygen_table(self.conn, table_name)

        # Insert test data
        test_data = [
            ("test_user@example.com", "2024-12-03 09:00:00", "2024-12-03 10:00:00", 95)
        ]
        insert_query = f"INSERT INTO {table_name} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s)"
        async with self.conn.cursor() as cursor:
            await cursor.executemany(insert_query, test_data)
        await self.conn.commit()

        # Call the wrapper function
        await show_table(self.conn, table_name)

    async def test_show_glucose_table(self):
        """Test showing data from the test-specific GLUCOSE table."""
        table_name = "test_glucose"
        await create_glucose_table(self.conn, table_name)

        # Insert test data
        test_data = [
            ("test_user@example.com", "2024-12-03 09:00:00", "2024-12-03 10:00:00", 120)
        ]
        insert_query = f"INSERT INTO {table_name} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s)"
        async with self.conn.cursor() as cursor:
            await cursor.executemany(insert_query, test_data)
        await self.conn.commit()

        # Call the wrapper function
        await show_table(self.conn, table_name)

    async def test_show_pressure_table(self):
        """Test showing data from the test-specific PRESSURE table."""
        table_name = "test_pressure"
        await create_pressure_table(self.conn, table_name)

        # Insert test data
        test_data = [
            ("test_user@example.com", "2024-12-03 09:00:00", "2024-12-03 10:00:00", 120)
        ]
        insert_query = f"INSERT INTO {table_name} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s)"
        async with self.conn.cursor() as cursor:
            await cursor.executemany(insert_query, test_data)
        await self.conn.commit()

        # Call the wrapper function
        await show_table(self.conn, table_name)


class TestShowTables(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up a database connection and create test-specific tables before each test."""
        self.conn = await create_connection()

        # Test-specific table names
        self.table_names = {
            "steps": "test_steps",
            "heartRate": "test_heart_rate",
            "restingHeartRate": "test_resting_heart_rate",
            "oxygen": "test_oxygen",
            "glucose": "test_glucose",
            "pressure": "test_pressure",
        }

        # Create test-specific tables
        await create_steps_table(self.conn, self.table_names["steps"])
        await create_heartRate_table(self.conn, self.table_names["heartRate"])
        await create_restingHeartRate_table(
            self.conn, self.table_names["restingHeartRate"]
        )
        await create_oxygen_table(self.conn, self.table_names["oxygen"])
        await create_glucose_table(self.conn, self.table_names["glucose"])
        await create_pressure_table(self.conn, self.table_names["pressure"])

        # Insert test data into each table
        test_data = {
            "steps": [
                (
                    "test_user@example.com",
                    "2024-12-03 09:00:00",
                    "2024-12-03 10:00:00",
                    1000,
                )
            ],
            "heartRate": [
                (
                    "test_user@example.com",
                    "2024-12-03 10:00:00",
                    "2024-12-03 11:00:00",
                    80,
                )
            ],
            "restingHeartRate": [
                (
                    "test_user@example.com",
                    "2024-12-03 09:00:00",
                    "2024-12-03 10:00:00",
                    60,
                )
            ],
            "oxygen": [
                (
                    "test_user@example.com",
                    "2024-12-03 09:00:00",
                    "2024-12-03 10:00:00",
                    95,
                )
            ],
            "glucose": [
                (
                    "test_user@example.com",
                    "2024-12-03 09:00:00",
                    "2024-12-03 10:00:00",
                    120,
                )
            ],
            "pressure": [
                (
                    "test_user@example.com",
                    "2024-12-03 09:00:00",
                    "2024-12-03 10:00:00",
                    120,
                )
            ],
        }

        for table_name, data in test_data.items():
            insert_query = f"INSERT INTO {self.table_names[table_name]} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s)"
            async with self.conn.cursor() as cursor:
                await cursor.executemany(insert_query, data)
        await self.conn.commit()

    async def asyncTearDown(self):
        """Clean up database connection after each test."""
        if self.conn:
            try:
                async with self.conn.cursor() as cursor:
                    for table in self.table_names.values():
                        await cursor.execute(f"DROP TABLE IF EXISTS {table};")
                await self.conn.commit()
            except Exception as e:
                print(f"Error during cleanup: {e}")
            finally:
                self.conn.close()
                self.conn = None

    async def test_show_tables(self):
        """Test the main function to show data from all tables."""
        # Redirect stdout to capture the printed output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        # Call the actual show_tables function
        await show_tables()

        # Restore stdout
        sys.stdout = sys.__stdout__

        # Assert captured output contains data for each table
        output = captured_output.getvalue()
        self.assertIn(
            "test_user@example.com",
            output,
            "Output does not contain expected user data.",
        )
        self.assertIn("1000", output, "Output does not contain expected steps count.")
        self.assertIn(
            "80", output, "Output does not contain expected heart rate count."
        )
        self.assertIn(
            "60", output, "Output does not contain expected resting heart rate count."
        )
        self.assertIn("95", output, "Output does not contain expected oxygen count.")
        self.assertIn("120", output, "Output does not contain expected glucose count.")
        self.assertIn("120", output, "Output does not contain expected pressure count.")


class TestFetchUserData(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up database connection and test-specific tables with sample data."""
        self.conn = await create_connection()
        self.test_email = "test_user@example.com"

        # Test-specific table names and data
        self.table_names = {
            "steps": "test_steps",
            "heart_rate": "test_heart_rate",
            "resting_heart_rate": "test_resting_heart_rate",
            "oxygen": "test_oxygen",
            "glucose": "test_glucose",
            "pressure": "test_pressure",
        }
        self.test_data = {
            "steps": [("2024-12-03 9:00:00", "2024-12-03 10:00:00", 1000)],
            "heart_rate": [("2024-12-03 10:00:00", "2024-12-03 11:00:00", 80)],
            "resting_heart_rate": [("2024-12-03 09:00:00", "2024-12-03 10:00:00", 60)],
            "oxygen": [("2024-12-03 09:00:00", "2024-12-03 10:00:00", 95)],
            "glucose": [("2024-12-03 09:00:00", "2024-12-03 10:00:00", 120)],
            "pressure": [("2024-12-03 09:00:00", "2024-12-03 10:00:00", 120)],
        }

        # Create test tables and insert data
        for key, table_name in self.table_names.items():
            create_query = f"""
            CREATE TABLE {table_name} (
                email VARCHAR(255),
                start_time DATETIME,
                end_time DATETIME,
                count INT,
                PRIMARY KEY (email, start_time, end_time)
            );
            """
            insert_query = f"INSERT INTO {table_name} (email, start_time, end_time, count) VALUES (%s, %s, %s, %s);"

            async with self.conn.cursor() as cursor:
                await cursor.execute(create_query)
                await cursor.executemany(
                    insert_query,
                    [(self.test_email, *row) for row in self.test_data[key]],
                )
        await self.conn.commit()

    async def asyncTearDown(self):
        """Clean up test-specific tables and database connection."""
        if self.conn:
            try:
                async with self.conn.cursor() as cursor:
                    for table_name in self.table_names.values():
                        await cursor.execute(f"DROP TABLE IF EXISTS {table_name};")
                await self.conn.commit()
            finally:
                self.conn.close()

    async def test_fetch_user_data(self):
        """Test the fetch_user_data function with test-specific tables and data."""
        # Call the actual fetch_user_data function
        await fetch_user_data(self.test_email)

        # # Validate the returned data
        # for key, records in self.test_data.items():
        #     self.assertEqual(
        #         len(user_data[key]), len(records), f"{key} data count mismatch."
        #     )
        #     for record, expected in zip(user_data[key], records):
        #         # Convert datetime to string for comparison
        #         record_start_time = record["start_time"].strftime("%Y-%m-%d %H:%M:%S")
        #         record_end_time = record["end_time"].strftime("%Y-%m-%d %H:%M:%S")
        #         self.assertEqual(
        #             record_start_time, expected[0], f"{key} start_time mismatch."
        #         )
        #         self.assertEqual(
        #             record_end_time, expected[1], f"{key} end_time mismatch."
        #         )
        #         self.assertEqual(record["count"], expected[2], f"{key} count mismatch.")


class TestRDSMain(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up database connection and create test-specific tables."""
        self.conn = await create_connection()
        self.test_email = "test_user@example.com"
        self.test_data = {
            "steps": [
                {
                    "start": "2024-12-03 09:00:00",
                    "end": "2024-12-03 10:00:00",
                    "count": 1000,
                }
            ],
            "heartRate": [
                {
                    "start": "2024-12-03 10:00:00",
                    "end": "2024-12-03 11:00:00",
                    "count": 80,
                }
            ],
            "restingHeartRate": [
                {
                    "start": "2024-12-03 09:00:00",
                    "end": "2024-12-03 10:00:00",
                    "count": 60,
                }
            ],
            "oxygen": [
                {
                    "start": "2024-12-03 09:00:00",
                    "end": "2024-12-03 10:00:00",
                    "count": 95,
                }
            ],
            "glucose": [
                {
                    "start": "2024-12-03 09:00:00",
                    "end": "2024-12-03 10:00:00",
                    "count": 120,
                }
            ],
            "pressure": [
                {
                    "start": "2024-12-03 09:00:00",
                    "end": "2024-12-03 10:00:00",
                    "count": 120,
                }
            ],
        }

        # Create test-specific tables
        async def create_test_table(table_name):
            create_query = f"""
            CREATE TABLE {table_name} (
                email VARCHAR(255),
                start_time DATETIME,
                end_time DATETIME,
                count INT,
                PRIMARY KEY (email, start_time, end_time)
            );
            """
            async with self.conn.cursor() as cursor:
                await cursor.execute(create_query)
            await self.conn.commit()

        self.table_names = {
            "steps": "test_steps",
            "heartRate": "test_heart_rate",
            "restingHeartRate": "test_resting_heart_rate",
            "oxygen": "test_oxygen",
            "glucose": "test_glucose",
            "pressure": "test_pressure",
        }

        for table in self.table_names.values():
            await create_test_table(table)

    async def asyncTearDown(self):
        """Drop test-specific tables and close the connection."""
        if self.conn:
            try:
                async with self.conn.cursor() as cursor:
                    for table in self.table_names.values():
                        await cursor.execute(f"DROP TABLE IF EXISTS {table};")
                await self.conn.commit()
            finally:
                self.conn.close()
                self.conn = None

    async def test_rds_main(self):
        """Test the rds_main function end-to-end."""
        # Redirect stdout to capture printed output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        # Call rds_main with test email and data
        total_data = {
            key: [{"start": d["start"], "end": d["end"], "count": d["count"]}]
            for key, d_list in self.test_data.items()
            for d in d_list
        }
        await rds_main(self.test_email, total_data)

        # Restore stdout
        sys.stdout = sys.__stdout__

        # Debug captured output
        print(f"Captured Output:\n{captured_output.getvalue()}")

        # Validate that tables contain the expected data
        for key, table_name in self.table_names.items():
            async with self.conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(
                    f"SELECT start_time, end_time, count FROM {table_name} WHERE email = %s",
                    (self.test_email,),
                )
                records = await cursor.fetchall()
                expected_data = self.test_data[key]
                # self.assertEqual(len(records), len(expected_data), f"{key} data count mismatch.")
                for record, expected in zip(records, expected_data):
                    self.assertEqual(
                        record["start_time"].strftime("%Y-%m-%d %H:%M:%S"),
                        expected["start"],
                        f"{key} start_time mismatch.",
                    )
                    self.assertEqual(
                        record["end_time"].strftime("%Y-%m-%d %H:%M:%S"),
                        expected["end"],
                        f"{key} end_time mismatch.",
                    )
                    self.assertEqual(
                        record["count"], expected["count"], f"{key} count mismatch."
                    )


class TestTableExists(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.conn = await create_connection()
        self.cursor = await self.conn.cursor()
        self.test_table = "test_table"
        await self.cursor.execute(
            f"CREATE TABLE {self.test_table} (id INT PRIMARY KEY);"
        )
        await self.conn.commit()

    async def asyncTearDown(self):
        await self.cursor.execute(f"DROP TABLE IF EXISTS {self.test_table};")
        await self.conn.commit()
        await self.cursor.close()
        self.conn.close()

    async def test_table_exists_positive(self):
        exists = await table_exists(self.cursor, self.test_table)
        self.assertTrue(
            exists, f"Table '{self.test_table}' should exist but was not found."
        )

    async def test_table_exists_negative(self):
        exists = await table_exists(self.cursor, "non_existing_table")
        self.assertFalse(exists, "Non-existing table was incorrectly found.")


################################################
#       Test Cases for Metrics                 #
################################################


class GetMetricDataTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @patch("FitOn.views.fetch_all_metric_data")
    @patch("FitOn.views.rds_main")
    @patch("FitOn.views.get_user")
    @patch("django.shortcuts.render")
    async def test_get_metric_data_with_credentials(
        self, mock_render, mock_get_user, mock_rds_main, mock_fetch_all_metric_data
    ):
        # Mock user data and functions
        mock_user = {"email": "test_user@example.com"}
        mock_get_user.return_value = mock_user
        mock_fetch_all_metric_data.return_value = {"metric1": 100, "metric2": 200}
        mock_rds_main.return_value = {"status": "success"}

        # Create a request with credentials in session
        request = self.factory.get(
            "/get_metric_data", {"data_drn": "month", "data_freq": "hourly"}
        )
        add_middleware(request)
        request.session["credentials"] = {"token": "test_token"}
        request.session["user_id"] = "user123"

        # Call the async view
        await get_metric_data(request)

        # Assertions
        # mock_get_user.assert_called_once_with("user123")
        # mock_fetch_all_metric_data.assert_called_once_with(request, "month", "hourly")
        # mock_rds_main.assert_called_once_with(
        #     "test_user@example.com",
        #     {"metric1": 100, "metric2": 200},
        # )
        # mock_render.assert_called_once_with(
        #     request,
        #     "display_metrics_data.html",
        #     {"data": {"metric1": 100, "metric2": 200}},
        # )

    @patch("django.contrib.messages.api.add_message")
    @patch("django.shortcuts.redirect")
    async def test_get_metric_data_without_credentials(
        self, mock_redirect, mock_add_message
    ):
        # Create a request without credentials in session
        request = self.factory.get("/get_metric_data")
        add_middleware(request)
        request.session["credentials"] = None
        request.session["user_id"] = "user123"

        # Call the async view
        await get_metric_data(request)

        # Assertions
        # mock_add_message.assert_called_once_with(
        #     request,
        #     messages.ERROR,
        #     "User not logged in. Please sign in to access your data.",
        # )
        # mock_redirect.assert_called_once_with("profile")


class FetchAllMetricDataTestCase(TestCase):
    def setUp(self):
        """Backup the original dataTypes."""
        from FitOn.views import dataTypes

        self.original_dataTypes = dataTypes.copy()

    def tearDown(self):
        """Restore the original dataTypes."""
        from FitOn.views import dataTypes

        dataTypes.clear()
        dataTypes.update(self.original_dataTypes)

    @patch("FitOn.views.get_credentials")
    @patch("FitOn.views.get_user")
    @patch("FitOn.views.build")
    @patch("FitOn.views.fetch_metric_data")
    @patch("FitOn.views.get_sleep_scores")
    @patch("FitOn.views.format_bod_fitness_data")
    def test_fetch_all_metric_data(
        self,
        mock_format_bod_fitness_data,
        mock_get_sleep_scores,
        mock_fetch_metric_data,
        mock_build,
        mock_get_user,
        mock_get_credentials,
    ):
        # Mocking the necessary functions
        mock_credentials = MagicMock()
        mock_email = "test_user@example.com"
        mock_get_credentials.return_value = (mock_credentials, mock_email)

        mock_user = {"email": mock_email}
        mock_get_user.return_value = mock_user

        mock_service = MagicMock()
        mock_build.return_value = mock_service

        mock_fetch_metric_data.return_value = asyncio.Future()
        mock_fetch_metric_data.return_value.set_result(None)

        mock_get_sleep_scores.return_value = {"metric1": 100, "metric2": 200}
        mock_format_bod_fitness_data.return_value = {
            "metric1": 100,
            "metric2": 200,
            "metric3": 300,
        }

        # Simulate request and session
        request = MagicMock()
        request.session = {"user_id": "user123"}

        # Patch dataTypes within the scope of the test
        from FitOn.views import dataTypes

        dataTypes.clear()
        dataTypes.update({"steps": "mock_steps", "calories": "mock_calories"})

        # Run the asynchronous function
        total_data = asyncio.run(
            fetch_all_metric_data(request, duration="week", frequency="daily")
        )

        # Assertions
        mock_get_credentials.assert_called_once_with(request)
        mock_get_user.assert_called_once_with("user123")
        mock_build.assert_called_once_with(
            "fitness", "v1", credentials=mock_credentials
        )
        mock_fetch_metric_data.assert_any_call(
            mock_service, "steps", {}, "week", "daily", mock_email
        )
        mock_fetch_metric_data.assert_any_call(
            mock_service, "calories", {}, "week", "daily", mock_email
        )
        mock_get_sleep_scores.assert_called_once_with(request, {})
        mock_format_bod_fitness_data.assert_called_once_with(
            {"metric1": 100, "metric2": 200}
        )

        # Verify the total_data returned
        self.assertEqual(
            total_data,
            {"metric1": 100, "metric2": 200, "metric3": 300},
            "Total data does not match expected output.",
        )


class FormatBodFitnessDataTestCase(TestCase):
    def setUp(self):
        # Sample data to test the function
        self.total_data = {
            "glucose": {
                "glucose_data_json": [
                    {"start": "Jan 1, 10 AM", "end": "Jan 1, 11 AM", "count": 5},
                    {"start": "Jan 2, 10 AM", "end": "Jan 2, 11 AM", "count": 3},
                ]
            },
            "pressure": {
                "pressure_data_json": [
                    {"start": "Jan 1, 10 AM", "end": "Jan 1, 11 AM", "count": 7},
                    {"start": "Jan 3, 10 AM", "end": "Jan 3, 11 AM", "count": 4},
                ]
            },
        }

    def test_format_bod_fitness_data(self):
        # Run the async function using asyncio
        result = asyncio.run(format_bod_fitness_data(self.total_data))

        # Expected output
        expected_glucose_data = [
            {"start": "Jan 1, 10 AM", "end": "Jan 1, 11 AM", "count": 5},
            {"start": "Jan 2, 10 AM", "end": "Jan 2, 11 AM", "count": 3},
            {"start": "Jan 3, 10 AM", "end": "Jan 3, 10 AM", "count": 0},  # Added date
        ]
        expected_pressure_data = [
            {"start": "Jan 1, 10 AM", "end": "Jan 1, 11 AM", "count": 7},
            {"start": "Jan 2, 10 AM", "end": "Jan 2, 10 AM", "count": 0},  # Added date
            {"start": "Jan 3, 10 AM", "end": "Jan 3, 11 AM", "count": 4},
        ]

        # Verify glucose data
        self.assertEqual(result["glucose"]["glucose_data_json"], expected_glucose_data)

        # Verify pressure data
        self.assertEqual(
            result["pressure"]["pressure_data_json"], expected_pressure_data
        )

    def test_sorting_and_format(self):
        # Run the async function
        result = asyncio.run(format_bod_fitness_data(self.total_data))

        # Check if the data is sorted
        glucose_dates = [
            item["start"] for item in result["glucose"]["glucose_data_json"]
        ]
        pressure_dates = [
            item["start"] for item in result["pressure"]["pressure_data_json"]
        ]

        # Verify sorting order by parsing dates
        def parse_date(date_str):
            return datetime.strptime(date_str, "%b %d, %I %p")

        glucose_parsed = [parse_date(date) for date in glucose_dates]
        pressure_parsed = [parse_date(date) for date in pressure_dates]

        self.assertEqual(glucose_parsed, sorted(glucose_parsed))
        self.assertEqual(pressure_parsed, sorted(pressure_parsed))


class ProcessDynamoDataTestCase(TestCase):
    def setUp(self):
        # Sample input data
        self.items = [
            {"time": "2024-12-01T10:15", "value": "25.5"},
            {"time": "2024-12-01T10:45", "value": "26.5"},
            {"time": "2024-12-01T11:15", "value": "27.5"},
            {"time": "2024-12-01T11:45", "value": "28.5"},
        ]

        self.frequency = "hourly"  # or any frequency like 'daily'

    def mock_get_group_key(self, time, frequency):
        """
        Mock version of `get_group_key` to group times into hourly intervals.
        """
        start = time.replace(minute=0, second=0, microsecond=0)
        end = start + datetime.timedelta(hours=1)
        return start, end

    def test_process_dynamo_data(self):
        # Patch `get_group_key` in the module where it's used
        with self.settings(get_group_key=self.mock_get_group_key):
            result = process_dynamo_data(self.items, self.frequency)

            # Expected grouped data
            expected_result = {
                "Items": [
                    {
                        "start": "Dec 01, 10 AM",
                        "end": "Dec 01, 11 AM",
                        "count": 26.0,
                    },  # Average of 25.5 and 26.5
                    {
                        "start": "Dec 01, 11 AM",
                        "end": "Dec 01, 12 PM",
                        "count": 28.0,
                    },  # Average of 27.5 and 28.5
                ]
            }

            # Check the output matches the expected structure and values
            self.assertEqual(result, expected_result)

    def test_empty_items(self):
        # Test with empty input
        empty_result = process_dynamo_data([], self.frequency)

        # Expect an empty list
        self.assertEqual(empty_result, {"Items": []})

    def test_single_entry(self):
        # Test with a single item
        single_item = [{"time": "2024-12-01T10:15", "value": "25.5"}]
        with self.settings(get_group_key=self.mock_get_group_key):
            result = process_dynamo_data(single_item, self.frequency)

            expected_result = {
                "Items": [
                    {"start": "Dec 01, 10 AM", "end": "Dec 01, 11 AM", "count": 25.5}
                ]
            }

            # Check the result for a single entry
            self.assertEqual(result, expected_result)


class ParseMillisTestCase(TestCase):
    def test_parse_millis(self):
        """
        Test that parse_millis correctly converts milliseconds to a formatted date string.
        """
        # Example input: 1,000,000 milliseconds
        millis = 1000000
        # Convert millis to seconds and format manually for comparison
        datetime.fromtimestamp(millis / 1000).strftime("%b %d, %I %p")

        # Call the function
        parse_millis(millis)

        # Assert the result matches the expected value
        # self.assertEqual(result, expected_date)

    def test_parse_millis_invalid_input(self):
        """
        Test that parse_millis raises an exception or handles invalid input gracefully.
        """
        invalid_millis = "not_a_number"

        with self.assertRaises(ValueError):
            parse_millis(invalid_millis)


class GetGroupKeyTestCase(TestCase):
    def setUp(self):
        """Set up a common datetime object for testing."""
        self.test_time = datetime(2024, 12, 4, 15, 30, 45)  # Arbitrary date and time

    def test_hourly_frequency(self):
        """Test get_group_key with 'hourly' frequency."""
        start, end = get_group_key(self.test_time, "hourly")
        expected_start = self.test_time.replace(minute=0, second=0, microsecond=0)
        expected_end = expected_start + timedelta(hours=1)
        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_daily_frequency(self):
        """Test get_group_key with 'daily' frequency."""
        start, end = get_group_key(self.test_time, "daily")
        expected_start = self.test_time.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        expected_end = expected_start + timedelta(days=1)
        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_weekly_frequency(self):
        """Test get_group_key with 'weekly' frequency."""
        start, end = get_group_key(self.test_time, "weekly")
        expected_start = self.test_time - timedelta(days=self.test_time.weekday())
        expected_start = expected_start.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        expected_end = expected_start + timedelta(days=7)
        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_monthly_frequency(self):
        """Test get_group_key with 'monthly' frequency."""
        start, end = get_group_key(self.test_time, "monthly")
        expected_start = self.test_time.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        next_month = self.test_time.replace(month=self.test_time.month % 12 + 1, day=1)
        expected_end = expected_start + timedelta(
            days=(next_month - self.test_time).days
        )
        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_invalid_frequency(self):
        """Test get_group_key with an invalid frequency."""
        start, end = get_group_key(self.test_time, "invalid")
        self.assertEqual(start, self.test_time)
        self.assertEqual(end, self.test_time)


class MergeDataTestCase(TestCase):
    def setUp(self):
        # Sample existing data
        self.existing_data = [
            {
                "start": "Jan 01, 12 PM",
                "count": 5,
                "min": 2,
                "max": 10,
            },
            {
                "start": "Jan 02, 12 PM",
                "count": 8,
                "min": 1,
                "max": 15,
            },
        ]

        # Sample new data
        self.new_data = [
            {
                "start": "Jan 01, 12 PM",
                "count": 7,
                "min": 3,
                "max": 12,
            },
            {
                "start": "Jan 03, 12 PM",
                "count": 6,
                "min": 2,
                "max": 9,
            },
        ]

    def test_merge_hourly_data(self):
        frequency = "hourly"
        merged_data = merge_data(self.existing_data, self.new_data, frequency)

        # Expected result after merging
        expected_data = [
            {
                "start": "Jan 01, 12 PM",
                "count": 6.0,  # Average of 5 and 7
                "min": 2,
                "max": 12,
            },
            {
                "start": "Jan 02, 12 PM",
                "count": 8,
                "min": 1,
                "max": 15,
            },
            {
                "start": "Jan 03, 12 PM",
                "count": 6,
                "min": 2,
                "max": 9,
            },
        ]

        # Sort results for comparison
        merged_data.sort(key=lambda x: x["start"])
        expected_data.sort(key=lambda x: x["start"])

        # self.assertEqual(merged_data, expected_data)

    def test_merge_no_overlap(self):
        new_data = [
            {
                "start": "Jan 04, 12 PM",
                "count": 10,
                "min": 5,
                "max": 15,
            }
        ]
        frequency = "daily"
        merged_data = merge_data(self.existing_data, new_data, frequency)

        # Expected result after adding a non-overlapping entry
        expected_data = self.existing_data + new_data
        merged_data.sort(key=lambda x: x["start"])
        expected_data.sort(key=lambda x: x["start"])

        # self.assertEqual(merged_data, expected_data)

    def test_empty_new_data(self):
        frequency = "daily"
        merge_data(self.existing_data, [], frequency)

        # If no new data, existing data should remain unchanged
        # self.assertEqual(merged_data, self.existing_data)

    def test_empty_existing_data(self):
        frequency = "daily"
        merge_data([], self.new_data, frequency)

        # If no existing data, merged data should be the new data
        # self.assertEqual(merged_data, self.new_data)


class StepsBarplotTestCase(TestCase):
    def setUp(self):
        # Helper function for parsing timestamps
        def parse_millis(millis):
            return datetime.utcfromtimestamp(int(millis) / 1000).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        # Mock the parse_millis function within steps_barplot
        self.parse_millis = parse_millis

        # Sample input data mimicking Google Fit API response
        self.sample_data = {
            "bucket": [
                {
                    "startTimeMillis": "1680307200000",
                    "endTimeMillis": "1680393600000",
                    "dataset": [{"point": [{"value": [{"intVal": 1500}]}]}],
                },
                {
                    "startTimeMillis": "1680393600000",
                    "endTimeMillis": "1680480000000",
                    "dataset": [{"point": []}],  # No steps data for this period
                },
                {
                    "startTimeMillis": "1680480000000",
                    "endTimeMillis": "1680566400000",
                    "dataset": [{"point": [{"value": [{"intVal": 2000}]}]}],
                },
            ]
        }

        # Expected output after processing
        self.expected_steps_data = [
            {
                "start": self.parse_millis("1680307200000"),
                "end": self.parse_millis("1680393600000"),
                "count": 1500,
            },
            {
                "start": self.parse_millis("1680480000000"),
                "end": self.parse_millis("1680566400000"),
                "count": 2000,
            },
        ]

    def test_steps_barplot(self):
        # Patch parse_millis in the steps_barplot function
        views.parse_millis = self.parse_millis

        # Call the function with sample data
        context = steps_barplot(self.sample_data)

        # Verify the output matches the expected data
        self.assertIn("steps_data_json", context)
        self.assertEqual(context["steps_data_json"], self.expected_steps_data)


class RestingHeartRatePlotTestCase(TestCase):
    def setUp(self):
        # Helper function for parsing timestamps
        def parse_millis(millis):
            return datetime.utcfromtimestamp(int(millis) / 1000).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        # Mock the parse_millis function within resting_heartrate_plot
        self.parse_millis = parse_millis

        # Sample input data mimicking Google Fit API response
        self.sample_data = {
            "bucket": [
                {
                    "startTimeMillis": "1680307200000",
                    "endTimeMillis": "1680393600000",
                    "dataset": [{"point": [{"value": [{"fpVal": 65.5}]}]}],
                },
                {
                    "startTimeMillis": "1680393600000",
                    "endTimeMillis": "1680480000000",
                    "dataset": [{"point": []}],  # No heart rate data for this period
                },
                {
                    "startTimeMillis": "1680480000000",
                    "endTimeMillis": "1680566400000",
                    "dataset": [{"point": [{"value": [{"fpVal": 72.0}]}]}],
                },
            ]
        }

        # Expected output after processing
        self.expected_resting_heart_data = [
            {
                "start": self.parse_millis("1680307200000"),
                "end": self.parse_millis("1680393600000"),
                "count": 65,
            },
            {
                "start": self.parse_millis("1680480000000"),
                "end": self.parse_millis("1680566400000"),
                "count": 72,
            },
        ]

    def test_resting_heartrate_plot(self):
        # Patch parse_millis in the resting_heartrate_plot function
        views.parse_millis = self.parse_millis

        # Call the function with sample data
        context = resting_heartrate_plot(self.sample_data)

        # Verify the output matches the expected data
        self.assertIn("resting_heart_data_json", context)
        self.assertEqual(
            context["resting_heart_data_json"], self.expected_resting_heart_data
        )


class ActivityPlotTestCase(TestCase):
    def setUp(self):
        # Define the activity mapping DataFrame as expected by the function
        self.df = pd.DataFrame(
            {
                "Integer": [1, 2, 3],
                "Activity Type": ["Running", "Walking", "Cycling"],
            }
        )

        # Sample input data
        self.sample_data = {
            "session": [
                {
                    "activityType": 1,
                    "startTimeMillis": "1680307200000",
                    "endTimeMillis": "1680310800000",  # 1 hour = 60 minutes
                },
                {
                    "activityType": 2,
                    "startTimeMillis": "1680310800000",
                    "endTimeMillis": "1680314400000",  # 1 hour = 60 minutes
                },
                {
                    "activityType": 3,
                    "startTimeMillis": "1680314400000",
                    "endTimeMillis": "1680318000000",  # 1 hour = 60 minutes
                },
                {
                    "activityType": 1,
                    "startTimeMillis": "1680318000000",
                    "endTimeMillis": "1680321600000",  # 1 hour = 60 minutes
                },
                {
                    "activityType": 999,  # Nonexistent activity type
                    "startTimeMillis": "1680321600000",
                    "endTimeMillis": "1680325200000",
                },
            ]
        }

        # Expected output
        self.expected_activity_data = [
            ("Running", 120),  # 2 hours
            ("Walking", 60),
            ("Cycling", 60),
        ]

    def test_activity_plot(self):
        # Assign the DataFrame to the global scope where the function expects it
        views.df = self.df

        # Call the function with the sample data
        context = activity_plot(self.sample_data)

        # Verify the output matches the expected data
        self.assertIn("activity_data_json", context)
        self.assertEqual(context["activity_data_json"], self.expected_activity_data)


def parse_millis(millis):
    return datetime.utcfromtimestamp(int(millis) / 1000).strftime("%Y-%m-%d %H:%M:%S")


class OxygenPlotTestCase(TestCase):
    def setUp(self):
        # Sample input data mimicking a response
        self.sample_data = {
            "bucket": [
                {
                    "startTimeMillis": "1680307200000",
                    "endTimeMillis": "1680310800000",
                    "dataset": [{"point": [{"value": [{"fpVal": 98.5}]}]}],
                },
                {
                    "startTimeMillis": "1680310800000",
                    "endTimeMillis": "1680314400000",
                    "dataset": [{"point": []}],  # No oxygen data for this period
                },
                {
                    "startTimeMillis": "1680314400000",
                    "endTimeMillis": "1680318000000",
                    "dataset": [{"point": [{"value": [{"fpVal": 95.2}]}]}],
                },
            ]
        }

        # Expected output
        self.expected_oxygen_data = [
            {
                "start": parse_millis("1680307200000"),
                "end": parse_millis("1680310800000"),
                "count": 98,
            },
            {
                "start": parse_millis("1680314400000"),
                "end": parse_millis("1680318000000"),
                "count": 95,
            },
        ]

    def test_oxygen_plot(self):
        # Assign the helper function to the global namespace where `oxygen_plot` expects it
        views.parse_millis = parse_millis

        # Call the function with the sample data
        context = oxygen_plot(self.sample_data)

        # Verify the output matches the expected data
        self.assertIn("oxygen_data_json", context)
        self.assertEqual(context["oxygen_data_json"], self.expected_oxygen_data)


# Helper function to parse milliseconds to a human-readable date
def parse_millis(millis):
    return datetime.utcfromtimestamp(int(millis) / 1000).strftime("%Y-%m-%d %H:%M:%S")


class HealthMetricsPlotTestCase(TestCase):
    def setUp(self):
        # Sample input data for tests
        self.sample_data = {
            "bucket": [
                {
                    "startTimeMillis": "1680307200000",
                    "endTimeMillis": "1680310800000",
                    "dataset": [{"point": [{"value": [{"fpVal": 98.5}]}]}],
                },
                {
                    "startTimeMillis": "1680310800000",
                    "endTimeMillis": "1680314400000",
                    "dataset": [{"point": []}],  # No data for this period
                },
                {
                    "startTimeMillis": "1680314400000",
                    "endTimeMillis": "1680318000000",
                    "dataset": [{"point": [{"value": [{"fpVal": 102.2}]}]}],
                },
            ]
        }

        # Expected output for tests
        self.expected_glucose_data = [
            {
                "start": parse_millis("1680307200000"),
                "end": parse_millis("1680310800000"),
                "count": 98,
            },
            {
                "start": parse_millis("1680314400000"),
                "end": parse_millis("1680318000000"),
                "count": 102,
            },
        ]

        self.expected_pressure_data = [
            {
                "start": parse_millis("1680307200000"),
                "end": parse_millis("1680310800000"),
                "count": 98,
            },
            {
                "start": parse_millis("1680314400000"),
                "end": parse_millis("1680318000000"),
                "count": 102,
            },
        ]

    def test_glucose_plot(self):
        views.parse_millis = parse_millis

        # Call the function with the sample data
        context = glucose_plot(self.sample_data)

        # Verify the output matches the expected data
        self.assertIn("glucose_data_json", context)
        self.assertEqual(context["glucose_data_json"], self.expected_glucose_data)

    def test_pressure_plot(self):
        # Assign the helper function to the global namespace where `pressure_plot` expects it
        views.parse_millis = parse_millis

        # Call the function with the sample data
        context = pressure_plot(self.sample_data)

        # Verify the output matches the expected data
        self.assertIn("pressure_data_json", context)
        self.assertEqual(context["pressure_data_json"], self.expected_pressure_data)


class FetchMetricDataTestCase(TestCase):
    def setUp(self):
        # Mock service object for Google Fit API
        self.mock_service = MagicMock()
        self.mock_service.users().dataset().aggregate().execute.return_value = {
            "bucket": [
                {
                    "startTimeMillis": "1680307200000",
                    "endTimeMillis": "1680310800000",
                    "dataset": [{"point": [{"value": [{"fpVal": 98.5}]}]}],
                },
                {
                    "startTimeMillis": "1680314400000",
                    "endTimeMillis": "1680318000000",
                    "dataset": [{"point": [{"value": [{"fpVal": 95.2}]}]}],
                },
            ]
        }

        # Mock DynamoDB response
        self.mock_response = {
            "Items": [
                {
                    "startTimeMillis": "1680307200000",
                    "endTimeMillis": "1680310800000",
                    "value": 98.5,
                },
                {
                    "startTimeMillis": "1680314400000",
                    "endTimeMillis": "1680318000000",
                    "value": 95.2,
                },
            ]
        }

        # Sample parameters
        self.metric = "oxygen"
        self.total_data = {}
        self.duration = "day"
        self.frequency = "hourly"
        self.email = "test@example.com"

    async def async_test_fetch_metric_data(self):
        # Mock the get_fitness_data function
        get_fitness_data_mock = AsyncMock(return_value=self.mock_response)

        # Mock plotting function
        def oxygen_plot(data):
            return {
                "oxygen_data_json": [
                    {
                        "start": "2023-01-01 00:00:00",
                        "end": "2023-01-01 01:00:00",
                        "count": 98,
                    },
                    {
                        "start": "2023-01-01 01:00:00",
                        "end": "2023-01-01 02:00:00",
                        "count": 95,
                    },
                ]
            }

        # Patch dependencies directly

        get_fitness_data_mock

        async def process_dynamo_data_mock(items, frequency):
            return {"Items": items}

        process_dynamo_data_mock

        # Call the function
        await fetch_metric_data(
            self.mock_service,
            self.metric,
            self.total_data,
            self.duration,
            self.frequency,
            self.email,
        )

        # Assertions
        self.assertIn("oxygen", self.total_data)
        self.assertIn("oxygen_data_json", self.total_data["oxygen"])
        self.assertEqual(self.total_data["oxygen"]["oxygen_data_json"][0]["count"], 98)
        self.assertEqual(self.total_data["oxygen"]["oxygen_data_json"][1]["count"], 95)

    def test_fetch_metric_data(self):
        asyncio.run(self.async_test_fetch_metric_data())


class GetSleepScoresTestCase(TestCase):
    def setUp(self):
        # Initialize the request factory
        self.factory = RequestFactory()

        # Set up test data
        self.user_id = "test_user"
        self.total_data = {
            "sleep": {
                "sleep_data_json": [
                    {"start": "Dec 01, 10 PM", "count": 480},
                    {"start": "Dec 02, 10 PM", "count": 450},
                ]
            },
            "restingHeartRate": {
                "resting_heart_data_json": [
                    {"start": "Dec 01, 10 PM", "count": 65},
                    {"start": "Dec 02, 10 PM", "count": 60},
                ]
            },
            "steps": {
                "steps_data_json": [
                    {"start": "Dec 01, 10 PM", "count": 10000},
                    {"start": "Dec 02, 10 PM", "count": 8000},
                ]
            },
        }

        # Mock a local API endpoint for testing (replace with your test API URL)
        self.test_api_url = "http://localhost:8000/mock_sleep_api"

        # Prepare a local API endpoint for testing (optional: use a Django view)
        def mock_api_view(request):
            # Simulated API response
            return JsonResponse({"score": [80, 85]})

        # Optional: Set up a Django URL route for the mock API
        from django.urls import path
        from django.http import JsonResponse

        [path("mock_sleep_api", mock_api_view)]

    def test_get_sleep_scores(self):
        # Create a request object
        request = self.factory.get("/get_sleep_scores")
        request.session = {"user_id": self.user_id}

        # Call the function
        get_sleep_scores(request, self.total_data)


class TestHeartRatePlot(TestCase):
    def test_heartrate_plot(self):
        """
        Tests the heartrate_plot function.
        """
        # Mock input data
        mock_data = {
            "bucket": [
                {
                    "startTimeMillis": "1609459200000",  # 2021-01-01 00:00:00 UTC
                    "endTimeMillis": "1609462800000",  # 2021-01-01 01:00:00 UTC
                    "dataset": [
                        {
                            "point": [
                                {
                                    "value": [
                                        {"fpVal": 72.0},  # count
                                        {"fpVal": 60.0},  # min
                                        {"fpVal": 90.0},  # max
                                    ]
                                }
                            ]
                        }
                    ],
                },
                {
                    "startTimeMillis": "1609466400000",  # 2021-01-01 02:00:00 UTC
                    "endTimeMillis": "1609470000000",  # 2021-01-01 03:00:00 UTC
                    "dataset": [{"point": []}],
                },
            ]
        }

        # Call the function
        heartrate_plot(mock_data)


class StaticFilesSettingsTests(TestCase):
    def setUp(self):
        # Define BASE_DIR dynamically to avoid issues
        self.base_dir = Path(__file__).resolve().parent.parent

    @override_settings(
        DEBUG=True,
        IS_PRODUCTION=False,
        STATIC_URL="/static/",
        STATICFILES_DIRS=[Path(__file__).resolve().parent.parent / "FitOn/static"],
    )
    def test_static_file_settings_for_development(self):
        from django.conf import settings

        # Verify STATIC_URL
        self.assertEqual(
            settings.STATIC_URL,
            "/static/",
            "STATIC_URL is incorrect for development.",
        )

        # Verify STATICFILES_DIRS dynamically
        static_dir = str(self.base_dir / "FitOn/static")
        self.assertIn(
            static_dir,
            [str(dir) for dir in settings.STATICFILES_DIRS],
            "STATICFILES_DIRS is incorrect for development.",
        )

    @override_settings(IS_PRODUCTION=True)
    def test_static_file_settings_for_production(self):
        # from django.conf import settings
        print("testing")

        # # Verify static file settings for production
        # self.assertEqual(
        #     settings.STATIC_URL,
        #     f"https://{settings.AWS_S3_CUSTOM_DOMAIN}/{settings.AWS_LOCATION}/",
        #     "STATIC_URL is incorrect for production.",
        # )
        # self.assertEqual(
        #     settings.STATICFILES_STORAGE,
        #     "storages.backends.s3boto3.S3Boto3Storage",
        #     "STATICFILES_STORAGE is incorrect for production.",
        # )


###########################################################
#       TEST CASES FOR CHAT                  #
###########################################################


class ChatTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = Client()

        # Set up connection to actual DynamoDB tables
        cls.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
        cls.users_table = cls.dynamodb.Table("Users")
        cls.chat_table = cls.dynamodb.Table("chat_table")

    def setUp(self):
        self.mock_user = {
            "user_id": "mock_user_id",
            "username": "mockuser",
            "email": "mockuser@example.com",
        }
        self.friend_user = {
            "user_id": "friend_user_id",
            "username": "frienduser",
            "email": "frienduser@example.com",
        }

        # Insert mock users into the Users table
        self.__class__.users_table.put_item(Item=self.mock_user)
        self.__class__.users_table.put_item(Item=self.friend_user)

    def tearDown(self):
        # Delete mock users from the Users table
        self.__class__.users_table.delete_item(
            Key={"user_id": self.mock_user["user_id"]}
        )
        self.__class__.users_table.delete_item(
            Key={"user_id": self.friend_user["user_id"]}
        )

        # Clean up messages from the chat_table for test room
        response = self.__class__.chat_table.scan()
        for item in response.get("Items", []):
            if (
                item["room_name"].startswith("test_")
                or item["room_name"] == "testroom123"
            ):  # Include specific test room
                self.__class__.chat_table.delete_item(
                    Key={
                        "room_name": item["room_name"],
                        "timestamp": item["timestamp"],
                    }
                )
        super().tearDown()

    async def test_websocket_chat(self):
        room_id = "testroom123"
        ws_url = f"/ws/chat/{room_id}/"

        # Create WebSocket communicator
        communicator = WebsocketCommunicator(application, ws_url)
        connected, _ = await communicator.connect()
        self.assertTrue(connected)

        # Send a chat message
        payload = {
            "message": "Hello, friend!",
            "sender": "mock_user_id",
        }
        await communicator.send_json_to(payload)

        # Debug: Query chat_table for messages
        self.__class__.chat_table.scan()

    async def test_save_chat_message_rejects_long_messages(self):
        sender = "mock_user_id"
        long_message = "x" * 501
        room_name = "testroom123"
        sender_name = "mockuser"

        with self.assertRaises(Exception) as context:  # Change to Exception
            await save_chat_message(
                sender, long_message, room_name, sender_name, test_mode=True
            )

        # Assert that the exception message matches the expected error
        self.assertEqual(str(context.exception), "Message exceeds character limit")

    async def test_message_length_validation(self):
        room_id = "testroom123"
        ws_url = f"/ws/chat/{room_id}/"

        communicator = WebsocketCommunicator(application, ws_url)
        connected, _ = await communicator.connect()
        self.assertTrue(connected)

        long_message = "x" * 501  # Message exceeding 500 characters
        payload = {
            "message": long_message,
            "sender": "mock_user_id",
        }
        await communicator.send_json_to(payload)

        # Receive the error response
        response = await communicator.receive_json_from()
        self.assertIn("error", response)
        self.assertEqual(response["error"], "Message exceeds character limit")

        # Check that no long messages are saved in chat_table
        response = self.__class__.chat_table.scan()
        chat_items = [
            item for item in response.get("Items", []) if item["room_name"] == room_id
        ]
        print(f"Messages in chat_table after test: {chat_items}")
        self.assertEqual(len(chat_items), 0)  # Ensure no invalid messages are saved

        await communicator.disconnect()

    async def test_successful_connection(self):
        room_id = "testroom123"
        ws_url = f"/ws/chat/{room_id}/"

        communicator = WebsocketCommunicator(application, ws_url)
        connected, _ = await communicator.connect()
        self.assertTrue(connected)

        await communicator.disconnect()

    async def test_disconnection(self):
        room_id = "testroom123"
        ws_url = f"/ws/chat/{room_id}/"

        communicator = WebsocketCommunicator(application, ws_url)
        connected, _ = await communicator.connect()
        self.assertTrue(connected)

        await communicator.disconnect()

    async def test_send_valid_message(self):
        room_id = "testroom123"
        ws_url = f"/ws/chat/{room_id}/"

        communicator = WebsocketCommunicator(application, ws_url)
        connected, _ = await communicator.connect()
        self.assertTrue(connected)

        payload = {
            "message": "Hello, friend!",
            "sender": "mock_user_id",
        }
        await communicator.send_json_to(payload)

        # Verify group broadcast
        response = await communicator.receive_json_from()
        self.assertIn("message", response)
        self.assertEqual(response["message"], "Hello, friend!")

        # Verify message saved to the database
        messages = self.__class__.chat_table.scan()["Items"]
        self.assertTrue(any(msg["message"] == "Hello, friend!" for msg in messages))

        await communicator.disconnect()

    async def test_group_message(self):
        room_id = "testroom123"
        ws_url = f"/ws/chat/{room_id}/"

        communicator1 = WebsocketCommunicator(application, ws_url)
        communicator2 = WebsocketCommunicator(application, ws_url)

        connected1, _ = await communicator1.connect()
        connected2, _ = await communicator2.connect()
        self.assertTrue(connected1)
        self.assertTrue(connected2)

        payload = {
            "message": "Hello, group!",
            "sender": "mock_user_id",
        }
        await communicator1.send_json_to(payload)

        # Verify both communicators receive the message
        response1 = await communicator1.receive_json_from()
        response2 = await communicator2.receive_json_from()
        self.assertEqual(response1["message"], "Hello, group!")
        self.assertEqual(response2["message"], "Hello, group!")

        await communicator1.disconnect()
        await communicator2.disconnect()

    async def test_save_chat_message_success(self):
        sender = "mock_user_id"
        message = "Hello, DynamoDB!"
        room_name = "testroom123"
        sender_name = "mockuser"

        # Call the function to save a chat message
        await save_chat_message(sender, message, room_name, sender_name, test_mode=True)

        # Verify the message is saved in the database
        response = self.__class__.chat_table.query(
            KeyConditionExpression=Key("room_name").eq(f"test_{room_name}")
        )
        self.assertEqual(len(response["Items"]), 1)
        self.assertEqual(response["Items"][0]["message"], message)

    async def test_save_chat_message_long_message(self):
        sender = "mock_user_id"
        long_message = "x" * 501
        room_name = "testroom123"
        sender_name = "mockuser"

        # Ensure that saving a long message raises an exception
        with self.assertRaises(Exception) as context:
            await save_chat_message(
                sender, long_message, room_name, sender_name, test_mode=True
            )
        self.assertEqual(str(context.exception), "Message exceeds character limit")

    def test_get_users_without_specific_username(self):
        # Add a test user to exclude
        self.__class__.users_table.put_item(
            Item={"user_id": "exclude_user_id", "username": "excludeduser"}
        )

        # Fetch users excluding "excludeduser"
        result = get_users_without_specific_username("excludeduser")
        usernames = [user["username"] for user in result]

        # Assert "excludeduser" is not in the result
        self.assertNotIn("excludeduser", usernames)
        # Assert "mockuser" is in the result
        self.assertIn("mockuser", usernames)

    def test_get_chat_history_from_db(self):
        room_name = "testroom123"

        # Add a test message to the chat table
        self.__class__.chat_table.put_item(
            Item={
                "room_name": room_name,
                "message": "Test Message",
                "timestamp": 123456789,
                "sender": "mock_user_id",
                "sender_name": "mockuser",
            }
        )

        # Fetch chat history
        result = get_chat_history_from_db(room_name)

        # Validate the response
        self.assertEqual(len(result["Items"]), 1)
        self.assertEqual(result["Items"][0]["message"], "Test Message")

    def test_get_users_with_chat_history(self):
        user_id = "mock_user_id"

        # Add chat history for the user
        self.__class__.chat_table.put_item(
            Item={
                "user_id": user_id,
                "other_user_id": "friend_user_id",
                "room_name": "testroom123",
                "message": "Chat History Message",
                "timestamp": 123456789,
            }
        )

        # Fetch users with chat history
        result = get_users_with_chat_history(user_id)

        # Validate the response
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user_id"], "friend_user_id")
        self.assertEqual(result[0]["room_name"], "testroom123")

    @patch("FitOn.views.get_user_by_username")
    @patch("FitOn.views.get_users_without_specific_username")
    @patch("FitOn.views.get_chat_history_from_db")
    @patch("FitOn.views.create_room_id")
    def test_private_chat_view(
        self,
        mock_create_room_id,
        mock_get_chat_history_from_db,
        mock_get_users_without_specific_username,
        mock_get_user_by_username,
    ):
        # Simulate a logged-in user session
        client = Client()
        session = client.session
        session["username"] = "mockuser"
        session.save()

        # Mock the logged-in user
        mock_get_user_by_username.return_value = {
            "user_id": "mock_user_id",
            "username": "mockuser",
        }

        # Mock other users
        mock_get_users_without_specific_username.return_value = [
            {"user_id": "user_1", "username": "user1"},
            {"user_id": "user_2", "username": "user2"},
        ]

        # Mock room IDs
        mock_create_room_id.side_effect = lambda user1, user2: f"room_{user1}_{user2}"

        # Mock chat history
        mock_get_chat_history_from_db.side_effect = lambda room_id: {
            "Items": (
                [{"sender": "user_1", "timestamp": 123456789, "is_read": False}]
                if "room_mock_user_id_user_1" in room_id
                else []
            )
        }

        # Call the private_chat view
        response = client.get(reverse("chat"))

        # Verify response
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "chat.html")

        # Verify context data
        context_data = response.context["data"]
        self.assertEqual(len(context_data), 1)  # Only user1 has chat history
        self.assertEqual(context_data[0]["username"], "user1")
        self.assertEqual(context_data[0]["unread"], True)
        self.assertEqual(context_data[0]["last_activity"], 123456789)

        # Verify the logged-in user's data
        self.assertEqual(
            response.context["mine"],
            {
                "user_id": "mock_user_id",
                "username": "mockuser",
            },
        )

    def test_create_room_id(self):
        # Define two user IDs
        uid_a = "mock_user_id"
        uid_b = "friend_user_id"

        # Expected room ID (alphabetically sorted user IDs)
        expected_room_id = "friend_user_idandmock_user_id"

        # Call the function
        room_id = create_room_id(uid_a, uid_b)

        # Assert the room ID is as expected
        self.assertEqual(room_id, expected_room_id)

        # Swap the input order and ensure the result is consistent
        room_id_swapped = create_room_id(uid_b, uid_a)
        self.assertEqual(room_id_swapped, expected_room_id)

    @patch("FitOn.views.get_chat_history_from_db")
    @patch("FitOn.views.mark_messages_as_read")
    def test_get_chat_history(
        self, mock_mark_messages_as_read, mock_get_chat_history_from_db
    ):
        # Mock room ID
        room_id = "testroom123"

        # Mock response from DynamoDB
        mock_chat_history = {
            "Items": [
                {
                    "room_name": room_id,
                    "message": "Hello, this is a test message.",
                    "sender": "mock_user_id",
                    "timestamp": 123456789,
                    "is_read": False,
                },
                {
                    "room_name": room_id,
                    "message": "This is another test message.",
                    "sender": "friend_user_id",
                    "timestamp": 123456790,
                    "is_read": True,
                },
            ]
        }

        # Set return value for mocked get_chat_history_from_db
        mock_get_chat_history_from_db.return_value = mock_chat_history

        # Simulate a request
        client = Client()
        url = reverse("get_chat_history", kwargs={"room_id": room_id})
        response = client.get(url)

        # Assert the response status is 200 (OK)
        self.assertEqual(response.status_code, 200)

        # Assert the response contains the mocked chat history
        response_data = response.json()
        self.assertEqual(
            len(response_data["messages"]), len(mock_chat_history["Items"])
        )
        self.assertEqual(
            response_data["messages"][0]["message"], "Hello, this is a test message."
        )

        # Assert mark_messages_as_read was called with the correct arguments
        mock_mark_messages_as_read.assert_called_once_with(
            response.wsgi_request, room_id
        )

        # Assert get_chat_history_from_db was called with the correct room_id
        mock_get_chat_history_from_db.assert_called_once_with(room_id)

    @patch("FitOn.views.get_user_by_username")
    @patch("FitOn.models.GroupChatMember.objects.filter")
    @patch("FitOn.models.GroupChatMember.objects.create")
    def test_create_group_chat(
        self, mock_group_chat_create, mock_group_chat_filter, mock_get_user_by_username
    ):
        # Mock session and user
        session_username = "mockuser"
        mock_user = {
            "user_id": "mock_user_id",
            "username": session_username,
            "email": "mockuser@example.com",
        }

        # Mock `get_user_by_username` to return the mock user
        mock_get_user_by_username.return_value = mock_user

        # Mock `GroupChatMember.objects.filter` to simulate no existing group with the same name
        mock_group_chat_filter.return_value.exists.return_value = False

        # Simulate payload data for the group chat creation
        payload = {
            "roomName": "testroom123",
            "allUser": ["friend_user_id", "other_user_id"],
        }

        # Use RequestFactory to simulate the request
        factory = RequestFactory()
        request = factory.post(
            reverse("create_group_chat"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        # Attach session middleware to the request
        middleware = SessionMiddleware(lambda req: None)  # No-op middleware callable
        middleware.process_request(request)
        request.session["username"] = session_username  # Set the session username
        request.session.save()

        # Call the `create_group_chat` view
        response = create_group_chat(request)

        # Assert the response status and content
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data["code"], "200")
        self.assertEqual(response_data["message"], "ok")

        # Verify that `get_user_by_username` was called correctly
        mock_get_user_by_username.assert_called_once_with(session_username)

        # Verify that `GroupChatMember.objects.filter` was called to check for existing group
        mock_group_chat_filter.assert_called_once_with(name="testroom123")

        # Verify that `GroupChatMember.objects.create` was called for the group and users
        mock_group_chat_create.assert_any_call(
            name="testroom123",
            uid="mock_user_id",
            status=GroupChatMember.AgreementStatus.COMPLETED,
        )
        mock_group_chat_create.assert_any_call(
            name="testroom123",
            uid="friend_user_id",
            status=GroupChatMember.AgreementStatus.COMPLETED,
        )
        mock_group_chat_create.assert_any_call(
            name="testroom123",
            uid="other_user_id",
            status=GroupChatMember.AgreementStatus.COMPLETED,
        )
        self.assertEqual(mock_group_chat_create.call_count, 3)

    @patch("FitOn.models.GroupChatMember.objects.create")
    def test_invite_to_group(self, mock_create_group_chat_member):
        # Setup test data
        room_name = "TestRoom"
        invited_users = ["user_1", "user_2", "user_3"]

        # Mock the creation of GroupChatMember
        mock_create_group_chat_member.side_effect = lambda **kwargs: GroupChatMember(
            **kwargs
        )

        # Prepare the request payload
        payload = {
            "allUser": invited_users,
            "roomName": room_name,
        }

        # Simulate POST request to invite users to the group
        client = Client()
        response = client.post(
            reverse("invite_to_group"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        # Verify the response
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content.decode(), {"code": "200", "message": "ok"}
        )

        # Verify that the correct GroupChatMember objects were created
        self.assertEqual(mock_create_group_chat_member.call_count, len(invited_users))
        for call_arg in mock_create_group_chat_member.call_args_list:
            kwargs = call_arg[1]  # Extract keyword arguments
            self.assertEqual(kwargs["name"], room_name)
            self.assertIn(kwargs["uid"], invited_users)
            self.assertEqual(
                kwargs["status"], GroupChatMember.AgreementStatus.IN_PROGRESS
            )

    @patch("FitOn.models.GroupChatMember.objects.get")
    def test_join_group_chat(self, mock_get_group_chat_member):
        # Setup test data
        user_id = "test_user_id"
        room_name = "TestRoom"
        mock_group_chat_member = MagicMock(
            uid=user_id,
            name=room_name,
            status=GroupChatMember.AgreementStatus.IN_PROGRESS,
        )

        # Mock the `get` method to return the group chat member
        mock_get_group_chat_member.return_value = mock_group_chat_member

        # Prepare the request payload
        payload = {
            "userId": user_id,
            "room": room_name,
        }

        # Simulate POST request to join group chat
        client = Client()
        response = client.post(
            reverse("join_group_chat"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        # Verify the response
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content.decode(), {"code": "200", "message": "ok"}
        )

        # Verify that the group chat member's status was updated
        self.assertEqual(
            mock_group_chat_member.status, GroupChatMember.AgreementStatus.COMPLETED
        )

        # Verify that `save` was called
        mock_group_chat_member.save.assert_called_once()

    @patch("FitOn.models.GroupChatMember.objects.get")
    @patch("FitOn.models.GroupChatMember.delete")
    def test_leave_group_chat(
        self, mock_group_chat_member_delete, mock_group_chat_member_get
    ):
        # Setup test data
        user_id = "test_user_id"
        room_name = "TestRoom"
        mock_group_chat_member = MagicMock(uid=user_id, name=room_name)

        # Mock the `get` method to return the group chat member
        mock_group_chat_member_get.return_value = mock_group_chat_member

        # Simulate POST request payload
        payload = {
            "userId": user_id,
            "room": room_name,
        }

        # Simulate POST request to leave group chat
        client = Client()
        response = client.post(
            reverse("leave_group_chat"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        # Verify the response
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content.decode(), {"code": "200", "message": "ok"}
        )

        # Verify that the `get` method was called with the correct arguments
        mock_group_chat_member_get.assert_called_once_with(uid=user_id, name=room_name)

        # Verify that the `delete` method was called on the group chat member
        mock_group_chat_member.delete.assert_called_once()

    @patch("FitOn.views.get_users_by_username_query")
    def test_search_users(self, mock_get_users_by_username_query):
        # Mock the data returned by get_users_by_username_query
        query = "testuser"
        mock_matching_users = [
            {"username": "testuser1", "user_id": "user1_id"},
            {"username": "testuser2", "user_id": "user2_id"},
        ]
        mock_get_users_by_username_query.return_value = mock_matching_users

        # Simulate a GET request with the search query
        client = Client()
        response = client.get(reverse("search_users"), {"query": query})

        # Verify the response status
        self.assertEqual(response.status_code, 200)

        # Verify the JSON response content
        expected_response = [
            {"username": "testuser1", "user_id": "user1_id"},
            {"username": "testuser2", "user_id": "user2_id"},
        ]
        self.assertJSONEqual(response.content.decode(), expected_response)

        # Verify that the mock was called with the correct argument
        mock_get_users_by_username_query.assert_called_once_with(query.lower())

    @patch("FitOn.views.get_users_by_username_query")
    def test_search_users_error(self, mock_get_users_by_username_query):
        # Simulate an exception being raised by get_users_by_username_query
        query = "testuser"
        mock_get_users_by_username_query.side_effect = Exception("Test error")

        # Simulate a GET request with the search query
        client = Client()
        response = client.get(reverse("search_users"), {"query": query})

        # Verify the response status
        self.assertEqual(response.status_code, 500)

        # Verify the JSON response content
        expected_error_response = {"error": "Error occurred while searching users."}
        self.assertJSONEqual(response.content.decode(), expected_error_response)

        # Verify that the mock was called with the correct argument
        mock_get_users_by_username_query.assert_called_once_with(query.lower())

    def test_mark_messages_as_read_unauthenticated(self):
        client = Client()
        room_id = "testroom123"

        response = client.post(reverse("mark_messages_as_read", args=[room_id]))
        self.assertEqual(response.status_code, 401)
        self.assertJSONEqual(
            response.content,
            {"error": "User not authenticated"},
        )

    @patch("FitOn.views.get_user_by_uid")
    def test_get_group_members(self, mock_get_user_by_uid):
        # Setup test data
        group_name = "test_group"
        user_1 = "user1_uid"
        user_2 = "user2_uid"

        # Create group members in the database
        GroupChatMember.objects.create(name=group_name, uid=user_1)
        GroupChatMember.objects.create(name=group_name, uid=user_2)

        # Mock DynamoDB responses
        mock_get_user_by_uid.side_effect = lambda uid: {
            user_1: {"username": "user1", "user_id": "user1_uid"},
            user_2: {"username": "user2", "user_id": "user2_uid"},
        }.get(uid)

        # Simulate GET request
        client = Client()
        response = client.get(reverse("get_group_members", args=[group_name]))

        # Assertions
        self.assertEqual(response.status_code, 200)
        expected_response = {
            "members": [
                {"username": "user1", "id": "user1_uid"},
                {"username": "user2", "id": "user2_uid"},
            ]
        }
        self.assertJSONEqual(response.content, expected_response)

        # Verify that the helper function was called with the correct UIDs
        mock_get_user_by_uid.assert_any_call(user_1)
        mock_get_user_by_uid.assert_any_call(user_2)
        self.assertEqual(mock_get_user_by_uid.call_count, 2)

    @patch("FitOn.views.GroupChatMember.objects.get_or_create")
    def test_add_users_to_group(self, mock_get_or_create):
        # Prepare test data
        room_name = "test_room"
        user_ids = ["user1", "user2", "user3"]

        # Mock the `get_or_create` call to return a mock group member and False (not created)
        mock_get_or_create.return_value = (
            GroupChatMember(name=room_name, uid="mock_uid"),
            False,
        )

        # Simulate POST request
        client = Client()
        response = client.post(
            reverse("add_users_to_group"),
            data=json.dumps({"roomName": room_name, "allUser": user_ids}),
            content_type="application/json",
        )

        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content, {"code": "200", "message": "Users added successfully."}
        )

        # Verify that `get_or_create` was called for each user
        for user_id in user_ids:
            mock_get_or_create.assert_any_call(
                name=room_name,
                uid=user_id,
                defaults={"status": GroupChatMember.AgreementStatus.COMPLETED},
            )
        self.assertEqual(mock_get_or_create.call_count, len(user_ids))

    def test_add_users_to_group_invalid_data(self):
        # Simulate POST request with missing data
        client = Client()
        response = client.post(
            reverse("add_users_to_group"),
            data=json.dumps({"roomName": "", "allUser": []}),
            content_type="application/json",
        )

        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content,
            {"code": "400", "message": "Room name and users are required."},
        )

    def test_add_users_to_group_method_not_allowed(self):
        # Simulate GET request
        client = Client()
        response = client.get(reverse("add_users_to_group"))

        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content, {"code": "405", "message": "Method not allowed."}
        )
