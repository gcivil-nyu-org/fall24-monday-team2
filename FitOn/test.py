from datetime import datetime, timedelta
from django.test import TestCase, Client
from unittest.mock import patch, MagicMock
from google.oauth2.credentials import Credentials
from django.urls import reverse
from . import dynamodb
import boto3
from django.contrib.auth.models import User
import time
import json
from .views import SCOPES

last_week_date = (datetime.now() - timedelta(days=7)).isoformat()
another_date = (datetime.now() - timedelta(days=5)).isoformat()


class ForumTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = Client()

        # Set up DynamoDB with Moto
        cls.dynamodb = boto3.resource("dynamodb", region_name="us-west-2")

        # Create mock tables for threads and posts
        cls.threads_table = cls.dynamodb.create_table(
            TableName="threads",
            KeySchema=[{"AttributeName": "ThreadID", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "ThreadID", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        cls.posts_table = cls.dynamodb.create_table(
            TableName="posts",
            KeySchema=[{"AttributeName": "PostID", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "PostID", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        time.sleep(10)  # Ensure tables are ready

    def setUp(self):
        # User setup and login
        self.client = Client()
        self.user = User.objects.create_user(username="testuser", password="12345")
        self.client.login(username="testuser", password="12345")

        # Insert test data
        self.threads_table.put_item(
            Item={
                "ThreadID": "123",
                "UserID": "test_user",
                "Title": "Test Thread",
                "Content": "This is a test content",
                "CreatedAt": last_week_date,
                "ReplyCount": 0,
            }
        )
        self.threads_table.put_item(
            Item={
                "ThreadID": "456",
                "UserID": "another_user",
                "Title": "Another Thread",
                "Content": "This is another test content",
                "CreatedAt": another_date,
                "ReplyCount": 2,
            }
        )
        time.sleep(5)  # Ensure data is available for scan

        # Create a thread in DynamoDB to work with
        thread = dynamodb.create_thread(
            title="Test Thread", user_id="testuser", content="Test Content"
        )
        self.thread_id = thread["ThreadID"]

    def test_fetch_filtered_threads(self):
        threads = dynamodb.fetch_filtered_threads(username="test_user")
        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["UserID"], "test_user")

        threads = dynamodb.fetch_filtered_threads(thread_type="thread")
        self.assertTrue(all(thread["ReplyCount"] == 0 for thread in threads))

        start_date = (
            (datetime.now().replace(year=datetime.now().year - 1)).date().isoformat()
        )
        end_date = datetime.now().date().isoformat()
        threads = dynamodb.fetch_filtered_threads(
            start_date=start_date, end_date=end_date
        )
        self.assertGreaterEqual(len(threads), 1)

    def test_fetch_all_users(self):
        users = dynamodb.fetch_all_users()
        user_ids = [user["username"] for user in users]
        self.assertIn("test_user", user_ids)
        self.assertIn("another_user", user_ids)
        self.assertEqual(len(users), 5)

    def test_forum_view(self):
        response = self.client.get(reverse("forum"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "forums.html")
        self.assertIn("threads", response.context)
        self.assertIn("users", response.context)

    def test_like_post(self):
        like_url = reverse("thread_detail", args=[self.thread_id])
        response = self.client.post(
            like_url,
            json.dumps({"like": True}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["liked"])

        response = self.client.post(
            like_url,
            json.dumps({"like": False}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        data = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["liked"])

    def test_delete_post(self):
        dynamodb.create_post(
            thread_id=self.thread_id, user_id="testuser", content="Test Post Content"
        )

        post_id = "your_method_to_get_post_id_here"  # Replace with actual retrieval
        response = self.client.post(
            reverse("delete_post"),
            json.dumps({"post_id": post_id, "thread_id": self.thread_id}),
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "success")

    @classmethod
    def tearDownClass(cls):
        cls.dynamodb.Table("threads").delete()
        cls.dynamodb.Table("posts").delete()
        cls.threads_table.meta.client.get_waiter("table_not_exists").wait(
            TableName="threads"
        )
        cls.posts_table.meta.client.get_waiter("table_not_exists").wait(
            TableName="posts"
        )
        super().tearDownClass()


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
        print("Inside Auth Google Function\n")
        mock_instance = mock_flow.from_client_config.return_value
        mock_instance.authorization_url.return_value = (
            "http://mock-auth-url",
            "mock-state",
        )

        # Simulate a GET request to the authorization view
        response = self.client.get(reverse("authorize_google_fit"))
        print("Sessions: ", self.client.session.items())
        print("Response: \n", response)

        # Assertions to verify the response
        self.assertEqual(response.status_code, 302)  # Check if redirect status code
        self.assertIn("http://mock-auth-url", response.url)  # Verify redirection URL
        self.assertIn("mock-state", self.client.session)  # Check if state is in session

    @patch("FitOn.views.Flow")
    @patch("FitOn.views.Credentials")
    def test_callback_google_fit(self, mock_flow):
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

        # Set a user ID in the session
        session = self.client.session
        session["user_id"] = "mock_user_id"
        session["google_fit_state"] = "mock-state"
        session.save()

        # Simulate a GET request to the callback view
        response = self.client.get(reverse("callback_google_fit"))

        # Assertions
        self.assertEqual(
            response.status_code, 200
        )  # Adjust status code based on expected response
        self.assertIn(
            "Signed in Successfully", response.content.decode()
        )  # Check for success message

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
