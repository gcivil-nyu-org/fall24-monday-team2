import unittest
from datetime import datetime, timedelta
from django.test import TestCase, Client
from django.urls import reverse
import boto3
from .dynamodb import (
    fetch_filtered_threads,
    fetch_all_users,
    create_thread,
    create_post,
)
from django.contrib.auth.models import User
import time
import json

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
        cls.threads_table_main = cls.dynamodb.Table("ForumThreads")
        time.sleep(10)  # Ensure tables are ready

    def setUp(self):
        # User setup and login
        self.client = Client()
        another_user = User.objects.create_user(
            username="another_user", password="12345"
        )
        self.user = User.objects.create_user(username="test_user", password="12345")
        self.client.login(username="testuser", password="12345")

        # Insert test data
        self.threads_table_main.put_item(
            Item={
                "ThreadID": "123",
                "UserID": "test_user",
                "Title": "Test Thread",
                "Content": "This is a test content",
                "CreatedAt": last_week_date,
                "LikedBy": [],
            }
        )
        self.threads_table_main.put_item(
            Item={
                "ThreadID": "456",
                "UserID": "another_user",
                "Title": "Another Thread",
                "Content": "This is another test content",
                "CreatedAt": another_date,
                "LikedBy": [],
            }
        )
        time.sleep(5)  # Ensure data is available for scan

        # Create a thread in DynamoDB to work with
        thread = create_thread(
            title="Test Thread", user_id="test_user", content="Test Content"
        )
        self.thread_id = thread["ThreadID"]

    def test_fetch_filtered_threads(self):
        threads = fetch_filtered_threads(username="test_user")
        self.assertEqual(len(threads), 4)
        self.assertEqual(threads[0]["UserID"], "test_user")

        threads = fetch_filtered_threads(thread_type="thread")
        self.assertTrue(all(thread["ReplyCount"] == 0 for thread in threads))

        start_date = (
            (datetime.now().replace(year=datetime.now().year - 1)).date().isoformat()
        )
        end_date = datetime.now().date().isoformat()
        threads = fetch_filtered_threads(start_date=start_date, end_date=end_date)
        self.assertGreaterEqual(len(threads), 3)

    def test_fetch_all_users(self):
        users = fetch_all_users()
        user_ids = [user["username"] for user in users]
        self.assertIn("test_user", user_ids)
        self.assertIn("another_user", user_ids)
        self.assertEqual(len(users), 4)

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
        create_post(
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
        # Delete only the threads created by 'test_user' and 'another_user'
        users_to_delete = ["test_user", "another_user"]
        for user_id in users_to_delete:
            response = cls.threads_table_main.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr("UserID").eq(user_id)
            )
            for item in response.get("Items", []):
                # Ensure correct key structure in delete_item
                print("\nDeleting: ", item)
                cls.threads_table_main.delete_item(Key={"ThreadID": item["ThreadID"]})

        # Ensure tables are deleted after tests
        cls.dynamodb.Table("threads").delete()
        cls.dynamodb.Table("posts").delete()
        cls.threads_table.meta.client.get_waiter("table_not_exists").wait(
            TableName="threads"
        )
        cls.posts_table.meta.client.get_waiter("table_not_exists").wait(
            TableName="posts"
        )
        super().tearDownClass()
