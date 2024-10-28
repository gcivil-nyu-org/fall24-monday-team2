from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core import mail
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch

from FitOn.dynamodb import MockUser, users_table

class PasswordResetTests(TestCase):

    def setUp(self):
        self.user = MockUser({
            'user_id': 'ba98896a-a118-4b9c-ad06-1df8be4cf1a4',
            'username': 'tae1',
            'email': 'taeyeon2000.kim@gmail.com',
            'password': make_password('aaa')
        })

        users_table.put_item(Item={
            'user_id': self.user.pk,
            'username': self.user.username,
            'email': self.user.email,
            'password': self.user.password
        })
        self.client = Client()

    def test_password_reset_request_view(self):
        response = self.client.post(reverse('password_reset_request'), {'email': self.user.email})
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Password Reset Requested', mail.outbox[0].subject)
        self.assertRedirects(response, reverse('password_reset_done'))

    def test_set_new_password(self):
        # Generate UID and token
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        print(f"[DEBUG] Test UID: {uid}, Token: {token}")

        # Post the new password
        response = self.client.post(
            reverse('password_reset_confirm', args=[uid, token]),
            {
                'new_password': 'newpassword123',
                'confirm_password': 'newpassword123'
            },
            follow=False
        )

        print("[DEBUG] Response status code:", response.status_code)
        print("[DEBUG] Response content:", response.content.decode())

        # Check for redirect to the password reset complete page
        self.assertRedirects(response, reverse('password_reset_complete'))


    def test_invalid_email_password_reset_request(self):
        response = self.client.post(reverse('password_reset_request'), {'email': 'invalid@example.com'})
        self.assertContains(response, 'The email you entered is not registered', status_code=200)

