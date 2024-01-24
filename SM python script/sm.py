import csv
import boto3
from datetime import datetime

# Create a CSV file for storing Secrets Manager details
secrets_csv_file_path = 'secrets_details_all_regions.csv'

# Headers for the Secrets CSV file
secrets_csv_headers = ['Region', 'SecretID', 'SecretARN', 'CreatedBy', 'LastAccessedBy', 'LastUsedTimestamp']

# Open the Secrets CSV file and write headers
with open(secrets_csv_file_path, mode='w', newline='') as secrets_csv_file:
    secrets_csv_writer = csv.writer(secrets_csv_file)
    secrets_csv_writer.writerow(secrets_csv_headers)

    # Fetch all AWS regions dynamically using EC2 client
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    # Iterate over all regions
    for region in regions:
        # AWS Secrets Manager client for the current region
        secrets_manager_client_region = boto3.client('secretsmanager', region_name=region)

        # Fetch details about Secrets Manager secrets
        secrets = secrets_manager_client_region.list_secrets()['SecretList']
        for secret in secrets:
            secret_id = secret['ARN'].split(':secret:')[1]
            secret_arn = secret['ARN']

            # Fetch CloudTrail events for Secrets Manager secret creation
            cloudtrail_client = boto3.client('cloudtrail', region_name=region)
            response_creation = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'ResourceName', 'AttributeValue': secret_id},
                    {'AttributeKey': 'EventName', 'AttributeValue': 'CreateSecret'},
                ],
            )

            # Extract the creator's identity information from CloudTrail events
            created_by = 'N/A'
            if 'Events' in response_creation:
                events_creation = response_creation['Events']
                for event in events_creation:
                    user_identity = event.get('userIdentity', {})
                    if 'userName' in user_identity:
                        created_by = user_identity['userName']
                        break
                    elif 'principalId' in user_identity:
                        created_by = 'Root'
                        break

            # Fetch CloudTrail events for Secrets Manager secret access (GetSecretValue)
            response_access = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'ResourceName', 'AttributeValue': secret_id},
                    {'AttributeKey': 'EventName', 'AttributeValue': 'GetSecretValue'},
                ],
            )

            # Extract the last accessed time and username from GetSecretValue events
            last_accessed_time = 'N/A'
            last_accessed_by = 'N/A'
            if 'Events' in response_access:
                events_access = response_access['Events']
                access_times = [event.get('eventTime') for event in events_access if event.get('eventTime')]
                if access_times:
                    last_accessed_time = max(access_times).split('.')[0]  

                    # Extract the username from the latest GetSecretValue event
                    latest_access_event = max(events_access, key=lambda x: x.get('eventTime'))
                    user_identity = latest_access_event.get('userIdentity', {})
                    last_accessed_by = user_identity.get('userName', 'N/A')

            # Write data to CSV
            secrets_csv_writer.writerow([region, secret_id, secret_arn, created_by, last_accessed_by, last_accessed_time])

print(f"Secrets CSV file generated: {secrets_csv_file_path}")
