from datetime import datetime
from django.test import TestCase, Client, override_settings

# from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch, MagicMock
from google.oauth2.credentials import Credentials

# from django.contrib.messages.middleware import MessageMiddleware
# from django.contrib.sessions.middleware import SessionMiddleware
from django.urls import reverse
import boto3
import json


# import unittest

# from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password

# from django.contrib.sessions.models import Session
# from django.utils import timezone
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core import mail

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
    fetch_posts_for_thread,
    MockUser,
    # users_table,
)
from botocore.exceptions import ClientError
import pytz
from django.contrib import messages

# from django.contrib.messages import get_messages
# from .forms import (
#     SignUpForm,
#     SetNewPasswordForm,
#     ProfileForm,
#     validate_file_extension,
# )
# from .views import (
#     SCOPES,
#     homepage,
#     add_message,
#     perform_redirect,
#     login,
#     custom_logout,
#     signup,
# )
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

    def create_post(self):
        post = create_post("123", "test_user_123", "This is a test post")

        # Store the post ID for cleanup
        self.test_post_id = post["PostID"]

        # Assertions to verify the post details
        self.assertEqual(post["ThreadID"], "123")
        self.assertEqual(post["UserID"], "test_user_123")
        self.assertEqual(post["Content"], "This is a test post")

        # Verify that CreatedAt is a valid ISO format datetime string
        created_at = post["CreatedAt"]
        self.assertIsInstance(datetime.fromisoformat(created_at), datetime)

        # Verify that the post was inserted into the ForumPosts table
        response = self.posts_table.get_item(Key={"PostID": self.test_post_id})
        saved_post = response.get("Item", None)
        self.assertIsNotNone(saved_post)
        self.assertEqual(saved_post["PostID"], post["PostID"])
        self.assertEqual(saved_post["ThreadID"], post["ThreadID"])
        self.assertEqual(saved_post["UserID"], post["UserID"])
        self.assertEqual(saved_post["Content"], post["Content"])
        self.assertEqual(saved_post["CreatedAt"], post["CreatedAt"])

        posts = fetch_posts_for_thread(self.thread_id)

        # Assertions to verify the posts
        self.assertEqual(len(posts), 1)

        # Check the details of the first post
        self.assertEqual(posts[0]["ThreadID"], self.thread_id)
        self.assertEqual(posts[0]["UserID"], "test_user_123")
        self.assertEqual(posts[0]["Content"], "This is a test post")

        self.posts_table.delete_item(Key={"PostID": self.test_post_id})

    def tearDown(self):
        delete_threads_by_user("test_user_123")


###########################################################
#       TEST CASE FOR GOOGLE AUTHENTICATION               #
###########################################################


class GoogleAuthTestCase(TestCase):
    @classmethod
    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def setUpClass(cls):
        super().setUpClass()
        cls.client = Client()

    @patch("FitOn.views.Flow")
    def test_authorize_google_fit(self, mock_flow):
        # Mock the Flow object
        mock_instance = mock_flow.from_client_config.return_value
        mock_instance.authorization_url.return_value = (
            "http://mock-auth-url",
            "mock-state",
        )

        # Simulate a GET request to the authorization view
        response = self.client.get(reverse("authorize_google_fit"))

        # Save the session explicitly
        session = self.client.session
        session["google_fit_state"] = "mock-state"
        session.save()

        # Assertions
        self.assertEqual(response.status_code, 302)  # Check if redirect status code
        self.assertIn("http://mock-auth-url", response.url)  # Verify redirection URL
        # self.assertIn("mock-state", session)  # Check if state is in session
        self.assertEqual(session["google_fit_state"], "mock-state")  # Verify the value

    @patch("FitOn.views.get_user")
    @patch("FitOn.views.Flow")
    @patch("FitOn.views.Credentials")
    def test_callback_google_fit(self, mock_credentials, mock_flow, mock_get_user):
        # Set up a mock user return value
        mock_get_user.return_value = {
            "name": "Test User",
            "email": "testuser@example.com",
            "gender": "Other",
            # Add other fields as needed
        }

        # Set up the mock credentials
        mock_creds = MagicMock(spec=Credentials)
        mock_creds.token = "mock-token"
        mock_creds.refresh_token = "mock-refresh-token"
        mock_creds.token_uri = "mock-token-uri"
        mock_creds.client_id = "mock-client-id"
        mock_creds.client_secret = "mock-client-secret"
        mock_creds.scopes = SCOPES

        # Mock the Flow object and its methods
        mock_instance = mock_flow.from_client_config.return_value
        mock_instance.fetch_token.return_value = None
        mock_instance.credentials = mock_creds

        # Set a user ID and state in the session
        session = self.client.session
        session["user_id"] = "mock_user_id"
        session["google_fit_state"] = "mock-state"
        session.save()

        # Simulate a GET request to the callback view
        response = self.client.get(reverse("callback_google_fit"))

        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertIn("Signed in Successfully", response.content.decode())

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()


class GoogleAuthDelinkTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = Client()

    def setUp(self):
        # Simulate session with credentials for the delink test
        session = self.client.session
        session["credentials"] = {
            "token": "mock-token",
            "refresh_token": "mock-refresh-token",
            "token_uri": "mock-token-uri",
            "client_id": "mock-client-id",
            "client_secret": "mock-client-secret",
            "scopes": ["mock-scope"],
        }
        session.save()

    @patch("FitOn.views.requests.post")
    def test_delink_google_fit(self, mock_post):
        # Mock the response for the revoke endpoint
        mock_post.return_value.status_code = 200  # Simulate successful revocation

        response = self.client.post(reverse("delink_google_fit"), follow=True)

        # Assertions for final response status after following redirects
        self.assertEqual(
            response.status_code, 200
        )  # Expect the final status code to be 200 after redirects

        # Verify that the session no longer contains credentials
        session = self.client.session
        self.assertNotIn("credentials", session)

        # Check if the success message is added to the messages framework
        messages_list = list(messages.get_messages(response.wsgi_request))
        self.assertTrue(
            any(
                message.message == "Your Google account has been successfully delinked."
                and message.level == messages.SUCCESS
                for message in messages_list
            ),
            "Expected success message not found in messages framework.",
        )

        # Check if the revocation endpoint was called
        mock_post.assert_called_once_with(
            "https://accounts.google.com/o/oauth2/revoke",
            params={"token": "mock-token"},
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    def tearDown(self):
        # Clear the session and any test data after each test
        session = self.client.session
        if "credentials" in session:
            del session["credentials"]
            session.save()

        # Add other cleanup steps if necessary

    @classmethod
    def tearDownClass(cls):
        # Perform any additional cleanup if needed
        super().tearDownClass()


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
        print("Mock user inserted into DynamoDB for testing.")

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
