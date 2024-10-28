from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from FitOn.dynamodb import create_thread, delete_post, create_post  # Include create_post
import json
import uuid



class ForumTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="testuser", password="12345")
        self.client.login(username="testuser", password="12345")
        
        # Create a thread in DynamoDB to work with
        thread = create_thread(title="Test Thread", user_id="testuser", content="Test Content")
        self.thread_id = thread['ThreadID']  # Assume `create_thread` returns a dictionary with the thread's details

    
    def test_like_post(self):
        # Test liking the post
        like_url = reverse('thread_detail', args=[self.thread_id])
        response = self.client.post(like_url, json.dumps({'like': True}), content_type="application/json", HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertTrue(data['liked'])
        
        # Test unliking the post
        response = self.client.post(like_url, json.dumps({'like': False}), content_type="application/json", HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        data = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'success')
        self.assertFalse(data['liked'])

    def test_delete_post(self):
        # Create a post to delete
        create_post(thread_id=self.thread_id, user_id="testuser", content="Test Post Content")
        
        # Assuming you have a way to retrieve the post ID, e.g., from the returned post or directly from DynamoDB
        post_id = 'your_method_to_get_post_id_here'  # Replace with actual retrieval of the post ID

        # Delete the post
        response = self.client.post(reverse('delete_post'), json.dumps({'post_id': post_id, 'thread_id': self.thread_id}), content_type="application/json", HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')



    """
    def test_report_post(self):
        # Simulate a report post request
        report_url = reverse('thread_detail', args=[self.thread_id])
        response = self.client.post(report_url, json.dumps({'report': True}), content_type="application/json", HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data.get('message', ''), 'Report functionality coming soon!')
    """