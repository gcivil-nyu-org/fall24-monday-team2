import aiomysql
import boto3
import json
from datetime import datetime


# Function to convert date strings to MySQL-compatible datetime strings
def convert_to_mysql_datetime(date_str):
    dt = datetime.strptime(date_str, "%b %d, %I %p")
    mysql_datetime = dt.strftime("%Y-%m-%d %H:%M:%S")
    return mysql_datetime


# Asynchronous function to get RDS secrets from AWS Secrets Manager
async def get_secret_rds():
    d = {}
    client = boto3.client("secretsmanager", region_name="us-west-2")
    response = client.get_secret_value(SecretId="rds_credentials")
    response = json.loads(response["SecretString"])
    d["host"] = response.get("host")
    d["database"] = response.get("database")
    d["port"] = response.get("port")
    d["password"] = response.get("password")
    d["username"] = response.get("username")
    return d


# Asynchronous function to create a database connection
async def create_connection():
    d = await get_secret_rds()
    conn = await aiomysql.connect(
        host=d["host"],
        user=d["username"],
        password=d["password"],
        db=d["database"],
        port=int(d["port"]),
    )
    return conn


# Asynchronous function to create tables
async def create_table(conn, table_sql):
    async with conn.cursor() as cursor:
        await cursor.execute(table_sql)
    await conn.commit()


# Asynchronous function to insert data into tables
async def insert_data(conn, query, data):
    async with conn.cursor() as cursor:
        await cursor.execute(query, data)
    await conn.commit()


# Functions to create tables
async def create_steps_table(conn):
    table_sql = """
        CREATE TABLE IF NOT EXISTS STEPS (
            email VARCHAR(255),
            start_time DATETIME,
            end_time DATETIME,
            count INT,
            PRIMARY KEY (email, start_time, end_time)
        )
    """
    await create_table(conn, table_sql)


async def create_heartRate_table(conn):
    table_sql = """
        CREATE TABLE IF NOT EXISTS HEART_RATE (
            email VARCHAR(255),
            start_time DATETIME,
            end_time DATETIME,
            count INT,
            PRIMARY KEY (email, start_time, end_time)
        )
    """
    await create_table(conn, table_sql)


async def create_restingHeartRate_table(conn):
    table_sql = """
        CREATE TABLE IF NOT EXISTS RESTING_HEART_RATE (
            email VARCHAR(255),
            start_time DATETIME,
            end_time DATETIME,
            count INT,
            PRIMARY KEY (email, start_time, end_time)
        )
    """
    await create_table(conn, table_sql)


async def create_oxygen_table(conn):
    table_sql = """
        CREATE TABLE IF NOT EXISTS OXYGEN (
            email VARCHAR(255),
            start_time DATETIME,
            end_time DATETIME,
            count INT,
            PRIMARY KEY (email, start_time, end_time)
        )
    """
    await create_table(conn, table_sql)


async def create_glucose_table(conn):
    table_sql = """
        CREATE TABLE IF NOT EXISTS GLUCOSE (
            email VARCHAR(255),
            start_time DATETIME,
            end_time DATETIME,
            count INT,
            PRIMARY KEY (email, start_time, end_time)
        )
    """
    await create_table(conn, table_sql)


async def create_pressure_table(conn):
    table_sql = """
        CREATE TABLE IF NOT EXISTS PRESSURE (
            email VARCHAR(255),
            start_time DATETIME,
            end_time DATETIME,
            count INT,
            PRIMARY KEY (email, start_time, end_time)
        )
    """
    await create_table(conn, table_sql)


# Functions to insert data into tables
async def insert_into_steps_table(conn, email, start_time, end_time, count):
    await create_steps_table(conn)
    c_start_time = convert_to_mysql_datetime(start_time)
    c_end_time = convert_to_mysql_datetime(end_time)
    insert_sql = """
        INSERT INTO STEPS (email, start_time, end_time, count)
        VALUES (%s, %s, %s, %s)
    """
    try:
        await insert_data(conn, insert_sql, (email, c_start_time, c_end_time, count))
        print("Inserted into Steps Table successfully.")
    except Exception as e:
        print(f"Error: {e}")


async def insert_into_heartRate_table(conn, email, start_time, end_time, count):
    await create_heartRate_table(conn)
    c_start_time = convert_to_mysql_datetime(start_time)
    c_end_time = convert_to_mysql_datetime(end_time)
    insert_sql = """
        INSERT INTO HEART_RATE (email, start_time, end_time, count)
        VALUES (%s, %s, %s, %s)
    """
    try:
        await insert_data(conn, insert_sql, (email, c_start_time, c_end_time, count))
        print("Inserted into Heart Rate Table successfully.")
    except Exception as e:
        print(f"Error: {e}")


async def insert_into_restingHeartRate_table(conn, email, start_time, end_time, count):
    await create_restingHeartRate_table(conn)
    c_start_time = convert_to_mysql_datetime(start_time)
    c_end_time = convert_to_mysql_datetime(end_time)
    insert_sql = """
        INSERT INTO RESTING_HEART_RATE (email, start_time, end_time, count)
        VALUES (%s, %s, %s, %s)
    """
    try:
        await insert_data(conn, insert_sql, (email, c_start_time, c_end_time, count))
        print("Inserted into Resting Heart Rate Table successfully.")
    except Exception as e:
        print(f"Error: {e}")


async def insert_into_oxygen_table(conn, email, start_time, end_time, count):
    await create_oxygen_table(conn)
    c_start_time = convert_to_mysql_datetime(start_time)
    c_end_time = convert_to_mysql_datetime(end_time)
    insert_sql = """
        INSERT INTO OXYGEN (email, start_time, end_time, count)
        VALUES (%s, %s, %s, %s)
    """
    try:
        await insert_data(conn, insert_sql, (email, c_start_time, c_end_time, count))
        print("Inserted into Oxygen Table successfully.")
    except Exception as e:
        print(f"Error: {e}")


async def insert_into_glucose_table(conn, email, start_time, end_time, count):
    await create_glucose_table(conn)
    c_start_time = convert_to_mysql_datetime(start_time)
    c_end_time = convert_to_mysql_datetime(end_time)
    insert_sql = """
        INSERT INTO GLUCOSE (email, start_time, end_time, count)
        VALUES (%s, %s, %s, %s)
    """
    try:
        await insert_data(conn, insert_sql, (email, c_start_time, c_end_time, count))
        print("Inserted into Glucose Table successfully.")
    except Exception as e:
        print(f"Error: {e}")


async def insert_into_pressure_table(conn, email, start_time, end_time, count):
    await create_pressure_table(conn)
    c_start_time = convert_to_mysql_datetime(start_time)
    c_end_time = convert_to_mysql_datetime(end_time)
    insert_sql = """
        INSERT INTO PRESSURE (email, start_time, end_time, count)
        VALUES (%s, %s, %s, %s)
    """
    try:
        await insert_data(conn, insert_sql, (email, c_start_time, c_end_time, count))
        print("Inserted into Pressure Table successfully.")
    except Exception as e:
        print(f"Error: {e}")


# Main function to insert data into all tables
async def insert_into_tables(email, total_data):
    conn = await create_connection()
    for data_type, data_list in total_data.items():
        for entry in data_list.values():
            for d in entry:
                start_time = d["start"]
                end_time = d["end"]
                count = d["count"]
                if data_type == "steps":
                    await insert_into_steps_table(
                        conn, email, start_time, end_time, count
                    )
                elif data_type == "heartRate":
                    await insert_into_heartRate_table(
                        conn, email, start_time, end_time, count
                    )
                elif data_type == "restingHeartRate":
                    await insert_into_restingHeartRate_table(
                        conn, email, start_time, end_time, count
                    )
                elif data_type == "oxygen":
                    await insert_into_oxygen_table(
                        conn, email, start_time, end_time, count
                    )
                elif data_type == "glucose":
                    await insert_into_glucose_table(
                        conn, email, start_time, end_time, count
                    )
                elif data_type == "pressure":
                    await insert_into_pressure_table(
                        conn, email, start_time, end_time, count
                    )
    conn.close()

# Asynchronous functions to display data from tables
async def show_table(conn, table_name):
    try:
        async with conn.cursor() as cursor:
            await cursor.execute(f"SELECT * FROM {table_name}")
            rows = await cursor.fetchall()
            print(f"Data in the {table_name} table:")
            for row in rows:
                print(row)
    except Exception:
        print("")


# Wrapper functions for each table
async def show_steps_table(conn):
    await show_table(conn, "STEPS")


async def show_heartRate_table(conn):
    await show_table(conn, "HEART_RATE")


async def show_restingHeartRate_table(conn):
    await show_table(conn, "RESTING_HEART_RATE")


async def show_oxygen_table(conn):
    await show_table(conn, "OXYGEN")


async def show_glucose_table(conn):
    await show_table(conn, "GLUCOSE")


async def show_pressure_table(conn):
    await show_table(conn, "PRESSURE")


# Main function to show all tables
async def show_tables():
    conn = await create_connection()
    try:
        await show_steps_table(conn)
        await show_heartRate_table(conn)
        await show_restingHeartRate_table(conn)
        await show_oxygen_table(conn)
        await show_glucose_table(conn)
        await show_pressure_table(conn)
    finally:
        conn.close()


async def main(email, total_data):

    await insert_into_tables(email, total_data)
    await show_tables()


async def rds_main(email, total_data):
    # Directly await the main function
    await main(email, total_data)
