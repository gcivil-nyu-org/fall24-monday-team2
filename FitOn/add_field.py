import boto3
import os
import django

import sys
import os

# Add the project directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'FitOn.settings')
django.setup()

# Initialize the DynamoDB client
dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
chat_table = dynamodb.Table("chat_table")

def add_is_read_field():
    try:
        # Scan the table to get all items
        response = chat_table.scan()
        items = response.get("Items", [])

        # Update each item to add the 'is_read' field
        for item in items:
            # Only update if 'is_read' is not already present
            if "is_read" not in item:
                chat_table.update_item(
                    Key={
                        "room_name": item["room_name"],
                        "timestamp": item["timestamp"]
                    },
                    UpdateExpression="SET is_read = :val",
                    ExpressionAttributeValues={
                        ":val": False  # Default value for existing items
                    }
                )
                print(f"Updated item with room_name: {item['room_name']} and timestamp: {item['timestamp']}")
        
        print("Finished updating items with is_read field.")
    except Exception as e:
        print(f"Error adding is_read field: {e}")

# Run the script
add_is_read_field()
