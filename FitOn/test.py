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
    get_user_by_email
)
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password
from django.contrib.sessions.models import Session
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core import mail
from unittest.mock import patch
import time
import json

last_week_date = (datetime.now() - timedelta(days=7)).isoformat()
another_date = (datetime.now() - timedelta(days=5)).isoformat()


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
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def setUpClass(cls):
        super().setUpClass()
        cls.client = Client()
        
        # Set up mock DynamoDB
        cls.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
        existing_tables = cls.dynamodb.meta.client.list_tables()["TableNames"]
        if "users_password_reset" in existing_tables:
            cls.dynamodb.Table("users_password_reset").delete()
            time.sleep(2)  # Ensure deletion before recreation
        
        # Create a fresh mock table for password reset
        cls.users_table = cls.dynamodb.create_table(
            TableName="users_password_reset",
            KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        cls.users_table.meta.client.get_waiter("table_exists").wait(TableName="users_password_reset")

    def setUp(self):
        # Clear outbox and sessions
        mail.outbox = []
        Session.objects.all().delete()

        # Set up mock user for testing
        self.user = MockUser({
            "user_id": "mock_user_id",
            "username": "mockuser",
            "email": "mockuser@example.com",
            "password": make_password("mockpassword"),
            "is_active": True,
        })
        self.__class__.users_table.put_item(Item=self.user.__dict__)

    def tearDown(self):
        # Clear user data after each test
        self.__class__.users_table.delete_item(Key={"user_id": self.user.user_id})
        mail.outbox = []  # Reset outbox to ensure test isolation
        super().tearDown()

    @classmethod
    def tearDownClass(cls):
        # Cleanup the table after all tests
        cls.users_table.delete()
        cls.users_table.meta.client.get_waiter("table_not_exists").wait(TableName="users_password_reset")
        super().tearDownClass()

    def test_password_reset_request_view(self):
        # Send reset request to mock user's email
        response = self.client.post(reverse("password_reset_request"), {"email": self.user.email})
        print(f"Testing email send to: {self.user.email}")
        print(f"Outbox length after send: {len(mail.outbox)}")

        # Ensure one email was sent to mock user
        self.assertEqual(len(mail.outbox), 1, "Expected exactly one email to be sent.")
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            print(f"Email sent to: {email.to}")
            self.assertEqual(email.to, [self.user.email])

    @patch("django.contrib.auth.tokens.default_token_generator.make_token")
    def test_password_reset_link_in_email(self, mock_make_token):
        mock_make_token.return_value = "mocked-token"
        response = self.client.post(reverse("password_reset_request"), {"email": self.user.email})
        print(f"Testing email send to: {self.user.email}")
        print(f"Outbox length after send: {len(mail.outbox)}")

        self.assertEqual(len(mail.outbox), 1, "Expected one email in the outbox")
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            print(f"Email recipients: {email.to}")
            self.assertEqual(email.to, [self.user.email])

    # # 3. Token and UID Verification
    # def test_expired_token_password_reset_confirm(self):
    #     uid = urlsafe_base64_encode(force_bytes(self.user.pk))
    #     token = default_token_generator.make_token(self.user)
    #     with patch(
    #         "django.contrib.auth.tokens.default_token_generator.check_token",
    #         return_value=False,
    #     ):
    #         response = self.client.get(
    #             reverse("password_reset_confirm", args=[uid, token])
    #         )
    #         self.assertContains(
    #             response,
    #             "The password reset link is invalid or has expired.",
    #             status_code=200,
    #         )

    # def test_invalid_token_password_reset_confirm(self):
    #     uid = urlsafe_base64_encode(force_bytes(self.user.pk))
    #     invalid_token = "invalid-token"
    #     response = self.client.get(
    #         reverse("password_reset_confirm", args=[uid, invalid_token])
    #     )
    #     self.assertContains(
    #         response,
    #         "The password reset link is invalid or has expired.",
    #         status_code=200,
    #     )

    # def test_invalid_reset_link(self):
    #     uid = "invalid_uid"
    #     token = "invalid_token"
    #     response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))
    #     self.assertContains(
    #         response,
    #         "The password reset link is invalid or has expired.",
    #         status_code=200,
    #     )

    # def test_password_reset_for_inactive_user(self):
    #     self.user.is_active = False  # Set user as inactive
    #     self.__class__.users_table.put_item(
    #         Item={"user_id": self.user.pk, "is_active": False}
    #     )
    #     response = self.client.post(
    #         reverse("password_reset_request"), {"email": self.user.email}
    #     )
    #     self.assertContains(
    #         response, "The email you entered is not registered", status_code=200
    #     )

    # # 4. Password Reset Process
    # def test_set_new_password(self):
    #     token = default_token_generator.make_token(self.user)
    #     uid = urlsafe_base64_encode(force_bytes(self.user.pk))
    #     response = self.client.post(
    #         reverse("password_reset_confirm", args=[uid, token]),
    #         {"new_password": "newpassword123", "confirm_password": "newpassword123"},
    #         follow=False,
    #     )
    #     self.assertRedirects(response, reverse("password_reset_complete"))

    # def test_mismatched_passwords_on_reset(self):
    #     token = default_token_generator.make_token(self.user)
    #     uid = urlsafe_base64_encode(force_bytes(self.user.pk))
    #     response = self.client.post(
    #         reverse("password_reset_confirm", args=[uid, token]),
    #         {
    #             "new_password": "password123",
    #             "confirm_password": "password456",  # Mismatched password
    #         },
    #     )
    #     self.assertContains(response, "Passwords do not match.", status_code=200)

    # def test_password_mismatch_on_reset(self):
    #     uid = urlsafe_base64_encode(force_bytes(self.user.pk))
    #     token = default_token_generator.make_token(self.user)
    #     response = self.client.post(
    #         reverse("password_reset_confirm", args=[uid, token]),
    #         {"new_password": "newpassword123", "confirm_password": "wrongpassword"},
    #         follow=False,
    #     )
    #     self.assertContains(response, "Passwords do not match.", status_code=200)

    # # 5. Complete Flow and Success Verification
    # def test_successful_password_reset_login(self):
    #     token = default_token_generator.make_token(self.user)
    #     uid = urlsafe_base64_encode(force_bytes(self.user.pk))
    #     self.client.post(
    #         reverse("password_reset_confirm", args=[uid, token]),
    #         {"new_password": "newpassword123", "confirm_password": "newpassword123"},
    #         follow=False,
    #     )
    #     response = self.client.post(
    #         reverse("login"),
    #         {"username": self.user.username, "password": "newpassword123"},
    #     )
    #     self.assertRedirects(response, reverse("homepage"))

    # def test_successful_password_reset_flow(self):
    #     response = self.client.post(
    #         reverse("password_reset_request"), {"email": self.user.email}
    #     )
    #     self.assertRedirects(response, reverse("password_reset_done"))
    #     token = default_token_generator.make_token(self.user)
    #     uid = urlsafe_base64_encode(force_bytes(self.user.pk))
    #     response = self.client.post(
    #         reverse("password_reset_confirm", args=[uid, token]),
    #         {"new_password": "newpassword123", "confirm_password": "newpassword123"},
    #         follow=True,
    #     )
    #     self.assertRedirects(response, reverse("password_reset_complete"))
    #     login_response = self.client.post(
    #         reverse("login"),
    #         {"username": self.user.username, "password": "newpassword123"},
    #     )
    #     self.assertRedirects(login_response, reverse("homepage"))





