import json

from channels.generic.websocket import AsyncWebsocketConsumer

from .dynamodb import (
    get_user_by_uid,
    save_chat_message,
)  # Add function to save messages to DynamoDB


class ChatMessageConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope["url_route"]["kwargs"]["room_id"]

        self.room_group_name = f"direct_message_{self.room_id}"

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        payload = json.loads(text_data)
        message = payload["message"]
        sender = payload["sender"]
        sender_name = get_user_by_uid(sender).get("username")
        await save_chat_message(sender, message, self.room_id, sender_name)
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "direct_message",
                "message": message,
                "sender": sender,
                "sender_name": sender_name,
            },
        )

    async def direct_message(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "message": event["message"],
                    "sender": event["sender"],
                    "sender_name": event["sender_name"],
                }
            )
        )
