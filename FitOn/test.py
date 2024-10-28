from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core import mail
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch

from .dynamodb import MockUser, users_table


class PasswordResetTests(TestCase):

    # Sets up a mock user in the database for testing the password reset process
    def setUp(self):
        self.user = MockUser(
            {
                "user_id": "ba98896a-a118-4b9c-ad06-1df8be4cf1a4",
                "username": "tae1",
                "email": "taeyeon2000.kim@gmail.com",
                "password": make_password("aaa"),
            }
        )

        users_table.put_item(
            Item={
                "user_id": self.user.pk,
                "username": self.user.username,
                "email": self.user.email,
                "password": self.user.password,
            }
        )
        self.client = Client()

    # Tests that submitting a password reset request with a registered email
    # sends a reset email and redirects to the 'password_reset_done' page.
    def test_password_reset_request_view(self):
        response = self.client.post(
            reverse("password_reset_request"), {"email": self.user.email}
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Password Reset Requested", mail.outbox[0].subject)
        self.assertRedirects(response, reverse("password_reset_done"))

    # Tests setting a new password with a valid token and user ID,
    # ensuring the user is redirected to the 'password_reset_complete' page.
    def test_set_new_password(self):
        # Generate UID and token
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        print(f"[DEBUG] Test UID: {uid}, Token: {token}")

        # Post the new password
        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": "newpassword123", "confirm_password": "newpassword123"},
            follow=False,
        )

        print("[DEBUG] Response status code:", response.status_code)
        print("[DEBUG] Response content:", response.content.decode())

        # Check for redirect to the password reset complete page
        self.assertRedirects(response, reverse("password_reset_complete"))

    # Tests that submitting a password reset request with an unregistered email
    # returns an error message stating the email is not registered.
    def test_invalid_email_password_reset_request(self):
        response = self.client.post(
            reverse("password_reset_request"), {"email": "invalid@example.com"}
        )
        self.assertContains(
            response, "The email you entered is not registered", status_code=200
        )

    # Tests that an expired or invalid token during password reset confirmation
    # returns an error message indicating the token is invalid or expired.
    def test_expired_token_password_reset_confirm(self):
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        with patch(
            "django.contrib.auth.tokens.default_token_generator.check_token",
            return_value=False,
        ):
            response = self.client.get(
                reverse("password_reset_confirm", args=[uid, token])
            )

        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            status_code=200,
        )

    # Tests that the password reset email contains a valid reset link.
    @patch("django.contrib.auth.tokens.default_token_generator.make_token")
    def test_password_reset_link_in_email(self, mock_make_token):
        mock_make_token.return_value = "mocked-token"

        response = self.client.post(
            reverse("password_reset_request"), {"email": self.user.email}
        )

        self.assertEqual(len(mail.outbox), 1)

        email = mail.outbox[0]
        email_html_body = email.alternatives[0][0] if email.alternatives else ""

        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        reset_link = reverse("password_reset_confirm", args=[uid, "mocked-token"])

        self.assertIn(reset_link, email_html_body)

    # Tests that submitting mismatched passwords during the reset process
    # returns an error message indicating the passwords do not match.
    def test_mismatched_passwords_on_reset(self):
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {
                "new_password": "password123",
                "confirm_password": "password456",  # Mismatched password
            },
        )

        self.assertContains(response, "Passwords do not match.", status_code=200)

    # Tests that after a successful password reset, the user can log in with the new password.
    def test_successful_password_reset_login(self):
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": "newpassword123", "confirm_password": "newpassword123"},
            follow=False,
        )

        response = self.client.post(
            reverse("login"),
            {"username": self.user.username, "password": "newpassword123"},
        )

        self.assertRedirects(response, reverse("homepage"))

    # Tests that accessing an invalid reset link returns an error message
    # indicating that the reset link is invalid or expired.
    def test_invalid_reset_link(self):
        uid = "invalid_uid"
        token = "invalid_token"

        response = self.client.get(reverse("password_reset_confirm", args=[uid, token]))

        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            status_code=200,
        )

    # Tests that submitting an empty email field in the reset request form
    # returns an error message indicating that the field is required.
    def test_missing_email_on_reset_request(self):
        response = self.client.post(reverse("password_reset_request"), {"email": ""})

        self.assertContains(
            response, "This field is required.", html=True, status_code=200
        )

    # Tests that submitting a reset request with an invalid token
    # returns an error message indicating that the link is invalid or expired.
    def test_invalid_token_password_reset_confirm(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        invalid_token = "invalid-token"
        response = self.client.get(
            reverse("password_reset_confirm", args=[uid, invalid_token])
        )
        self.assertContains(
            response,
            "The password reset link is invalid or has expired.",
            status_code=200,
        )

    # Tests that accessing the password reset confirmation view with an expired token
    # returns an error message indicating that the reset link is invalid or expired.
    def test_expired_token_password_reset_confirm(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        with patch(
            "django.contrib.auth.tokens.default_token_generator.check_token",
            return_value=False,
        ):
            response = self.client.get(
                reverse("password_reset_confirm", args=[uid, token])
            )
            self.assertContains(
                response,
                "The password reset link is invalid or has expired.",
                status_code=200,
            )

    # Tests that attempting to reset the password with mismatched passwords
    # returns an error message indicating the mismatch.
    def test_password_mismatch_on_reset(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": "newpassword123", "confirm_password": "wrongpassword"},
            follow=False,
        )
        self.assertContains(response, "Passwords do not match.", status_code=200)

    # Tests that a password reset request for an inactive user returns
    # an error message indicating the email is not registered.
    def test_password_reset_for_inactive_user(self):
        self.user.is_active = False  # Set user as inactive
        users_table.put_item(Item={"user_id": self.user.pk, "is_active": False})
        response = self.client.post(
            reverse("password_reset_request"), {"email": self.user.email}
        )
        self.assertContains(
            response, "The email you entered is not registered", status_code=200
        )

    # Tests the complete flow of requesting a password reset, setting a new password,
    # and successfully logging in with the new password.
    def test_successful_password_reset_flow(self):
        # Request password reset
        response = self.client.post(
            reverse("password_reset_request"), {"email": self.user.email}
        )
        self.assertRedirects(response, reverse("password_reset_done"))

        # Get token and UID
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        # Reset password
        response = self.client.post(
            reverse("password_reset_confirm", args=[uid, token]),
            {"new_password": "newpassword123", "confirm_password": "newpassword123"},
            follow=True,
        )
        self.assertRedirects(response, reverse("password_reset_complete"))

        # Attempt to login with the new password
        login_response = self.client.post(
            reverse("login"),
            {"username": self.user.username, "password": "newpassword123"},
        )
        self.assertRedirects(login_response, reverse("homepage"))
