from django.test import TestCase
from .dynamodb import create_user, delete_user_by_username, get_user_by_email, get_user_by_uid, get_user, update_user_password, update_user, create_thread, delete_threads_by_user
import boto3
from django.contrib.auth.hashers import check_password
from botocore.exceptions import ClientError
from datetime import datetime
import json
import pytz

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
        self.assertIn("Item", response, "User was not found in DynamoDB after creation.")
        user = response["Item"]
        self.assertEqual(user["username"], self.user_data["username"])

    def test_get_user_by_email(self):
        # Ensure the user exists before testing retrieval
        create_user(**self.user_data)

        # Test get_user_by_email
        user_by_email = get_user_by_email(self.user_data["email"])
        self.assertIsNotNone(user_by_email, "get_user_by_email did not find the user.")
        self.assertEqual(user_by_email.email, self.user_data["email"], "Emails do not match.")
        self.assertEqual(user_by_email.username, self.user_data["username"], "Usernames do not match.")

    def test_get_user_by_uid(self):
        # Ensure the user exists before testing retrieval
        create_user(**self.user_data)

        # Test get_user_by_uid
        user_by_uid = get_user_by_uid(self.user_data["user_id"])
        self.assertIsNotNone(user_by_uid, "get_user_by_uid did not find the user.")
        self.assertEqual(user_by_uid["user_id"], self.user_data["user_id"], "User IDs do not match.")
        self.assertEqual(user_by_uid["username"], self.user_data["username"], "Usernames do not match.")

    def test_get_user(self):
        # Step 1: Ensure the user exists by calling create_user
        create_result = create_user(**self.user_data)
        self.assertTrue(create_result, "User creation failed.")

        # Step 2: Call get_user to retrieve the user by user_id
        retrieved_user = get_user(self.user_data["user_id"])

        # Step 3: Verify the retrieved user matches the expected data
        self.assertIsNotNone(retrieved_user, "get_user did not find the user.")
        self.assertEqual(retrieved_user["user_id"], self.user_data["user_id"], "User IDs do not match.")
        self.assertEqual(retrieved_user["username"], self.user_data["username"], "Usernames do not match.")
        self.assertEqual(retrieved_user["email"], self.user_data["email"], "Emails do not match.")
    
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
            "gender": {"Value": "F"}
        }

        # Step 2: Call update_user
        update_result = update_user(self.user_data["user_id"], update_data)
        self.assertIsNotNone(update_result, "User update failed.")

        # Step 3: Retrieve the user to verify updates
        updated_user = get_user(self.user_data["user_id"])
        self.assertIsNotNone(updated_user, "User not found after update.")

        # Step 4: Check that the updated fields match the expected values
        self.assertEqual(updated_user["email"], update_data["email"]["Value"], "Email update failed.")
        self.assertEqual(updated_user["name"], update_data["name"]["Value"], "Name update failed.")
        self.assertEqual(updated_user["gender"], update_data["gender"]["Value"], "Gender update failed.")
    
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
                ":d": datetime.now(pytz.timezone("US/Eastern")).isoformat()
            }
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
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["message"], "User has been unbanned", "Unban message should confirm unban success.")

        # Step 2: Verify the user is unbanned and punishment_date is removed
        unbanned_user = get_user(self.user_data["user_id"])
        self.assertFalse(unbanned_user["is_banned"], "User's is_banned should be False after unban.")
        self.assertNotIn("punishment_date", unbanned_user, "punishment_date should be removed when user is unbanned.")
    
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
            content=self.thread_data["content"]
        )

        # Verify that the thread has a ThreadID and CreatedAt
        self.assertIn("ThreadID", thread, "ThreadID should be generated and set.")
        self.assertIn("CreatedAt", thread, "CreatedAt should be generated and set.")

        # Step 2: Retrieve the thread from DynamoDB to verify it was added
        response = self.threads_table.get_item(Key={"ThreadID": thread["ThreadID"]})
        self.assertIn("Item", response, "Thread not found in DynamoDB after creation.")
        
        created_thread = response["Item"]
        self.assertEqual(created_thread["Title"], self.thread_data["title"], "Thread title does not match.")
        self.assertEqual(created_thread["UserID"], self.thread_data["user_id"], "Thread user_id does not match.")
        self.assertEqual(created_thread["Content"], self.thread_data["content"], "Thread content does not match.")
        self.assertEqual(created_thread["Likes"], 0, "Initial likes count should be 0.")
        self.assertEqual(created_thread["LikedBy"], [], "Initial LikedBy list should be empty.")

    # TODO: ADD DELETE_POST FUNCTION

    def test_delete_threads_by_user(self):
        # Step 1: Set up sample data
        user_id = "test_user_123"
        delete_threads_by_user(user_id)
        
        # Verify all threads for the user are deleted
        response = self.threads_table.scan(
            FilterExpression="UserID = :user",
            ExpressionAttributeValues={":user": user_id}
        )
        self.assertEqual(len(response["Items"]), 0, "All threads for the user should be deleted.")

    def tearDown(self):
        delete_threads_by_user("test_user_123")