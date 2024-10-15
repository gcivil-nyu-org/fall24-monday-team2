import boto3

# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')

# List all tables in DynamoDB
tables = list(dynamodb.tables.all())

if tables:
    print("Connected to DynamoDB! Available tables:")
    for table in tables:
        print(table.name)
else:
    print("No tables found or credentials not configured properly.")
