import unittest
from datetime import datetime
from django.test import TestCase, Client
from django.urls import reverse
# pip install moto
import moto
import boto3
from .dynamodb import fetch_filtered_threads, fetch_all_users
from .views import forum_view
import time

class ForumTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = Client()
        
        # Set up DynamoDB with Moto
        cls.dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
        
        # Create mock tables for threads and posts
        cls.threads_table = cls.dynamodb.create_table(
            TableName='threads',
            KeySchema=[{'AttributeName': 'ThreadID', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'ThreadID', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )
        
        cls.posts_table = cls.dynamodb.create_table(
            TableName='posts',
            KeySchema=[{'AttributeName': 'PostID', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'PostID', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

        time.sleep(10)

    def setUp(self):
        # Insert test data
        self.threads_table.put_item(
            Item={
                'ThreadID': '123',
                'UserID': 'test_user',
                'Title': 'Test Thread',
                'Content': 'This is a test content',
                'CreatedAt': datetime.now().isoformat(),
                'ReplyCount': 0
            }
        )
        self.threads_table.put_item(
            Item={
                'ThreadID': '456',
                'UserID': 'another_user',
                'Title': 'Another Thread',
                'Content': 'This is another test content',
                'CreatedAt': datetime.now().isoformat(),
                'ReplyCount': 2
            }
        )

        time.sleep(5)

        items = list(self.threads_table.scan()['Items'])
        #print("Inserted items in threads_table:", items)

    def test_fetch_filtered_threads(self):
        # Test username filter
        threads = fetch_filtered_threads(username='test_user')
        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]['UserID'], 'test_user')

        # Test type filter for "thread" (ReplyCount == 0)
        threads = fetch_filtered_threads(thread_type='thread')
        self.assertTrue(all(thread['ReplyCount'] == 0 for thread in threads))

        # Test date range filter (assuming dates set above are recent)
        start_date = (datetime.now().replace(year=datetime.now().year - 1)).date().isoformat()
        end_date = datetime.now().date().isoformat()
        threads = fetch_filtered_threads(start_date=start_date, end_date=end_date)
        self.assertGreaterEqual(len(threads), 1)  # At least one should match

        # Test search text filter
        # threads = fetch_filtered_threads(search_text='test content')
        # print(threads)
        # self.assertGreaterEqual(len(threads), 0)
        # self.assertIn('test content', threads[0]['Content'])

            

    def test_fetch_all_users(self):
        users = fetch_all_users()
        user_ids = [user['username'] for user in users]
        self.assertIn('test_user', user_ids)
        self.assertIn('another_user', user_ids)
        self.assertEqual(len(users), 5)  # Five unique users

    def test_forum_view(self):
        response = self.client.get(reverse('forum'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forums.html')
        self.assertIn('threads', response.context)
        self.assertIn('users', response.context)

    @classmethod
    def tearDownClass(cls):
        # Delete 'threads' and 'posts' tables after tests conclude
        print("Deleting tables threads and posts...")
        cls.dynamodb.Table('threads').delete()
        cls.dynamodb.Table('posts').delete()
        
        # Wait until tables are deleted to ensure cleanup completes
        cls.threads_table.meta.client.get_waiter('table_not_exists').wait(TableName='threads')
        cls.posts_table.meta.client.get_waiter('table_not_exists').wait(TableName='posts')
        
        super().tearDownClass()

