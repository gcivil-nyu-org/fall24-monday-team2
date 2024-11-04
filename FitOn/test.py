from datetime import datetime
from django.test import TestCase, Client
from unittest.mock import patch, MagicMock
from google.oauth2.credentials import Credentials
from django.urls import reverse
import boto3
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
)
from django.contrib.auth.hashers import check_password
from botocore.exceptions import ClientError
import pytz
from django.contrib import messages


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
        self.assertIsNotNone(user_by_uid, "get_user_by_uid did not find the user.")
        self.assertEqual(
            user_by_uid["user_id"], self.user_data["user_id"], "User IDs do not match."
        )
        self.assertEqual(
            user_by_uid["username"],
            self.user_data["username"],
            "Usernames do not match.",
        )

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

    # def test_toggle_ban_user(self):
    #     create_user(**self.user_data)
    #     user = get_user_by_uid(self.user_data["user_id"])
    #     print(user)
    #     print(user["username"])
    #     # Step 1: Ban the user by toggling is_banned
    #     self.client.post(
    #         "/toggle_ban_user/",
    #         data=json.dumps({"username": user["username"]}),
    #         content_type="application/json",
    #         HTTP_X_REQUESTED_WITH="XMLHttpRequest"
    #     )

    #     # Manually retrieve the user from DynamoDB and verify is_banned is True
    #     self.assertTrue(user["is_banned"], "User should be banned.")

    #     # Check that punishment_date is set
    #     self.assertIn("punishment_date", self.user_data, "punishment_date should be set when user is banned.")

    #     # Step 2: Unban the user by toggling is_banned again
    #     self.client.post(
    #         "/toggle_ban_user/",
    #         data=json.dumps({"username": self.user_data["username"]}),
    #         content_type="application/json",
    #         HTTP_X_REQUESTED_WITH="XMLHttpRequest"
    #     )

    #     # Manually retrieve the user from DynamoDB and verify is_banned is False
    #     unbanned_user = get_user(self.user_data["username"])
    #     self.assertFalse(unbanned_user["is_banned"], "User should be unbanned.")

    #     # Check that punishment_date is removed
    #     self.assertNotIn("punishment_date", unbanned_user, "punishment_date should be removed when user is unbanned.")

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
        user = get_user_by_uid(self.user_data["user_id"])
        print(user)
        print(user["is_banned"])

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
            unbanned_user["is_banned"], "User's is_banned should be False after unban."
        )
        self.assertNotIn(
            "punishment_date",
            unbanned_user,
            "punishment_date should be removed when user is unbanned.",
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

    # TODO: ADD DELETE_POST FUNCTION

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

    def tearDown(self):
        delete_threads_by_user("test_user_123")


###########################################################
#       TEST CASE FOR GOOGLE AUTHENTICATION               #
###########################################################


class GoogleAuthTestCase(TestCase):
    @classmethod
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
        print(session.items())

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
