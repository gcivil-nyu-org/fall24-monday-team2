import unittest
from datetime import datetime, timedelta
from django.test import TestCase, Client, override_settings
from django.urls import reverse
import boto3
from .dynamodb import (
    fetch_filtered_threads,
    fetch_all_users,
    create_thread,
    create_post,
    MockUser,
    users_table,
    get_user_by_email,
    get_user_by_uid,
)
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core import mail
from unittest.mock import patch
import time
import json

# last_week_date = (datetime.now() - timedelta(days=7)).isoformat()
# another_date = (datetime.now() - timedelta(days=5)).isoformat()


# class ForumTests(TestCase):
#     @classmethod
#     def setUpClass(cls):
#         super().setUpClass()
#         cls.client = Client()

#         # Set up DynamoDB with Moto
#         cls.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")

#         # Create mock tables for threads and posts
#         cls.threads_table = cls.dynamodb.create_table(
#             TableName="threads",
#             KeySchema=[{"AttributeName": "ThreadID", "KeyType": "HASH"}],
#             AttributeDefinitions=[{"AttributeName": "ThreadID", "AttributeType": "S"}],
#             ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
#         )

#         cls.posts_table = cls.dynamodb.create_table(
#             TableName="posts",
#             KeySchema=[{"AttributeName": "PostID", "KeyType": "HASH"}],
#             AttributeDefinitions=[{"AttributeName": "PostID", "AttributeType": "S"}],
#             ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
#         )
#         time.sleep(10)  # Ensure tables are ready

#     def setUp(self):
#         # User setup and login
#         self.client = Client()
#         self.user = User.objects.create_user(username="testuser", password="12345")
#         self.client.login(username="testuser", password="12345")

#         # Insert test data
#         self.threads_table.put_item(
#             Item={
#                 "ThreadID": "123",
#                 "UserID": "test_user",
#                 "Title": "Test Thread",
#                 "Content": "This is a test content",
#                 "CreatedAt": last_week_date,
#                 "ReplyCount": 0,
#             }
#         )
#         self.threads_table.put_item(
#             Item={
#                 "ThreadID": "456",
#                 "UserID": "another_user",
#                 "Title": "Another Thread",
#                 "Content": "This is another test content",
#                 "CreatedAt": another_date,
#                 "ReplyCount": 2,
#             }
#         )
#         time.sleep(5)  # Ensure data is available for scan

#         # Create a thread in DynamoDB to work with
#         thread = create_thread(
#             title="Test Thread", user_id="testuser", content="Test Content"
#         )
#         self.thread_id = thread["ThreadID"]

#     def test_fetch_filtered_threads(self):
#         threads = fetch_filtered_threads(username="test_user")
#         self.assertEqual(len(threads), 1)
#         self.assertEqual(threads[0]["UserID"], "test_user")

#         threads = fetch_filtered_threads(thread_type="thread")
#         self.assertTrue(all(thread["ReplyCount"] == 0 for thread in threads))

#         start_date = (
#             (datetime.now().replace(year=datetime.now().year - 1)).date().isoformat()
#         )
#         end_date = datetime.now().date().isoformat()
#         threads = fetch_filtered_threads(start_date=start_date, end_date=end_date)
#         self.assertGreaterEqual(len(threads), 1)

#     def test_fetch_all_users(self):
#         users = fetch_all_users()
#         user_ids = [user["username"] for user in users]
#         self.assertIn("test_user", user_ids)
#         self.assertIn("another_user", user_ids)
#         self.assertEqual(len(users), 5)

#     def test_forum_view(self):
#         response = self.client.get(reverse("forum"))
#         self.assertEqual(response.status_code, 200)
#         self.assertTemplateUsed(response, "forums.html")
#         self.assertIn("threads", response.context)
#         self.assertIn("users", response.context)

#     def test_like_post(self):
#         like_url = reverse("thread_detail", args=[self.thread_id])
#         response = self.client.post(
#             like_url,
#             json.dumps({"like": True}),
#             content_type="application/json",
#             HTTP_X_REQUESTED_WITH="XMLHttpRequest",
#         )
#         self.assertEqual(response.status_code, 200)
#         data = json.loads(response.content)
#         self.assertEqual(data["status"], "success")
#         self.assertTrue(data["liked"])

#         response = self.client.post(
#             like_url,
#             json.dumps({"like": False}),
#             content_type="application/json",
#             HTTP_X_REQUESTED_WITH="XMLHttpRequest",
#         )
#         data = json.loads(response.content)
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(data["status"], "success")
#         self.assertFalse(data["liked"])

#     def test_delete_post(self):
#         create_post(
#             thread_id=self.thread_id, user_id="testuser", content="Test Post Content"
#         )

#         post_id = "your_method_to_get_post_id_here"  # Replace with actual retrieval
#         response = self.client.post(
#             reverse("delete_post"),
#             json.dumps({"post_id": post_id, "thread_id": self.thread_id}),
#             content_type="application/json",
#             HTTP_X_REQUESTED_WITH="XMLHttpRequest",
#         )
#         self.assertEqual(response.status_code, 200)
#         data = json.loads(response.content)
#         self.assertEqual(data["status"], "success")

#     @classmethod
#     def tearDownClass(cls):
#         cls.dynamodb.Table("threads").delete()
#         cls.dynamodb.Table("posts").delete()
#         cls.threads_table.meta.client.get_waiter("table_not_exists").wait(
#             TableName="threads"
#         )
#         cls.posts_table.meta.client.get_waiter("table_not_exists").wait(
#             TableName="posts"
#         )
#         super().tearDownClass()


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
        response = self.client.post(
            reverse("password_reset_request"), {"email": "nonexistent@example.com"}
        )
        print("Testing password reset with a nonexistent email.")

        # Ensure no email was sent
        self.assertEqual(
            len(mail.outbox), 0, "Expected no email to be sent for non-existent email."
        )

    def test_password_reset_request_valid_email(self):
        # Test with the mock user's email
        response = self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )

        # Ensure an email was sent
        self.assertEqual(len(mail.outbox), 1, "Expected exactly one email to be sent.")
        email = mail.outbox[0]
        self.assertEqual(email.to, [self.mock_user.email])

    def test_password_reset_link_in_email(self):
        # Test if the password reset link is in the email
        response = self.client.post(
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
        response = self.client.post(
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
        # Set the 'is_active' attribute of the mock user to False before updating DynamoDB
        self.mock_user.is_active = False
        self.__class__.users_table.put_item(
            Item=self.mock_user.__dict__
        )  # Update the mock user in DynamoDB
        retrieved_user = get_user_by_uid(self.mock_user.user_id)
        print(f"User status after setting inactive: {retrieved_user.is_active}")

        # Attempt to send a password reset request for the inactive user
        response = self.client.post(
            reverse("password_reset_request"), {"email": self.mock_user.email}
        )
        self.assertContains(
            response, "The email you entered is not registered", status_code=200
        )

        # Ensure no email was sent
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
        response = self.client.post(
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
