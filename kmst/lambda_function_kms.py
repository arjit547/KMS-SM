import csv
import boto3
from datetime import datetime

def get_user_name(iam_client, principal_id):
    if principal_id == 'N/A':
        return 'N/A'

    try:
        response = iam_client.get_user(UserName=principal_id)
        return response['User']['UserName']
    except Exception as e:
        print(f"Error retrieving user name for principalId {principal_id}: {e}")
        return 'N/A'

def extract_iam_username_from_events(events, iam_client):
    for event in events:
        if 'userIdentity' in event and 'principalId' in event['userIdentity']:
            principal_id = event['userIdentity']['principalId']
            user_name = get_user_name(iam_client, principal_id)
            if user_name != 'N/A':
                return user_name
    return 'N/A'

def extract_last_access_time(events):
    access_times = [event['eventTime'] for event in events if 'eventTime' in event]
    return max(access_times) if access_times else 'N/A'

def lambda_handler(event, context):
    s3_bucket = event.get('S3_BUCKET', '')
    s3_folder = event.get('S3_FOLDER', '')
    kms_csv_key = f'{s3_folder}/kms_details_all_regions.csv'
    
    kms_client = boto3.client('kms')
    iam_client = boto3.client('iam')

    # Create a CSV file for storing KMS details
    kms_csv_file_path = '/tmp/kms_details_all_regions.csv'

    # Headers for the KMS CSV file
    kms_csv_headers = ['Region', 'ResourceID', 'ResourceName', 'CreatedBy', 'CreationDate', 'LastAccessedBy', 'LastAccessedTimestamp']

    # Open the KMS CSV file and write headers
    with open(kms_csv_file_path, mode='w', newline='') as kms_csv_file:
        kms_csv_writer = csv.writer(kms_csv_file)
        kms_csv_writer.writerow(kms_csv_headers)

        # Fetch all AWS regions dynamically using EC2 client
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

        # Iterate over all regions
        for region in regions:
            # AWS KMS client for the current region
            kms_client_region = boto3.client('kms', region_name=region)

            # Fetch details about KMS keys
            kms_keys = kms_client_region.list_keys()['Keys']
            for key in kms_keys:
                key_id = key['KeyId']
                key_name = key['KeyArn'].split('/')[-1]

                # Fetch KMS key metadata to get the creation date and creator information
                key_metadata = kms_client_region.describe_key(KeyId=key_id)['KeyMetadata']
                creation_date = key_metadata.get('CreationDate', 'N/A')
                creator_arn = key_metadata.get('Arn', 'N/A')
                creator_name = creator_arn.split('/')[-1]  # Extract the last part of the ARN as the creator's name

                # Check if the key was created by an AWS service
                key_manager = key_metadata.get('KeyManager', 'N/A')

                if key_manager == 'AWS':
                    # If created by an AWS service, set the creator as "AWS"
                    creator_name = key_manager
                else:
                    # If created by a customer, try to extract the IAM username from CloudTrail events
                    cloudtrail_client = boto3.client('cloudtrail', region_name=region)
                    response_create = cloudtrail_client.lookup_events(
                        LookupAttributes=[
                            {'AttributeKey': 'ResourceName', 'AttributeValue': key_id},
                            {'AttributeKey': 'EventName', 'AttributeValue': 'CreateKey'},
                        ],
                    )

                    create_key_events = response_create.get('Events', [])
                    creator_name = extract_iam_username_from_events(create_key_events, iam_client)

                    # Fetch CloudTrail events for KMS key access (Decrypt)
                    response_decrypt = cloudtrail_client.lookup_events(
                        LookupAttributes=[
                            {'AttributeKey': 'ResourceName', 'AttributeValue': key_id},
                            {'AttributeKey': 'EventName', 'AttributeValue': 'Decrypt'},
                        ],
                    )

                    # Extract the last accessed time from Decrypt events
                    decrypt_events = response_decrypt.get('Events', [])
                    last_accessed_time = extract_last_access_time(decrypt_events)

                    # Fetch KMS key aliases
                    key_aliases = [alias['AliasName'] for alias in kms_client_region.list_aliases(KeyId=key_id)['Aliases']]

                    # Write data to CSV
                    kms_csv_writer.writerow([region, key_id, key_aliases, creator_name, creation_date, 'N/A', last_accessed_time])

    # Upload CSV file to S3 bucket
    s3_client = boto3.client('s3')
    s3_client.upload_file(kms_csv_file_path, s3_bucket, kms_csv_key)

    print(f"KMS CSV file uploaded to S3: s3://{s3_bucket}/{kms_csv_key}")

    return {
        'statusCode': 200,
        'body': 'KMS Lambda Function Executed Successfully!'
    }
