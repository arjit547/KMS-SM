import boto3
import csv
import json

# Fetch all regions
ec2_client = boto3.client('ec2')
regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

# Open a CSV file for writing
with open('kms_events.csv', 'w', newline='') as csvfile:
    fieldnames = ['Region', 'KeyID', 'Aliases', 'EventName', 'LastEventTime', 'Username', 'SourceIP', 'CreationDate']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    # Write header row to CSV file
    writer.writeheader()

    # Iterate over each region
    for region in regions:
        # Fetch KMS client for the region
        kms_client = boto3.client('kms', region_name=region)
        
        # Fetch all KMS keys in the region
        keys_response = kms_client.list_keys()
        kms_keys = keys_response['Keys']
        
        # Iterate over each KMS key
        for kms_key in kms_keys:
            key_id = kms_key['KeyId']
            
            # Fetch aliases associated with the KMS key
            aliases_response = kms_client.list_aliases(KeyId=key_id)
            aliases = [alias['AliasName'] for alias in aliases_response.get('Aliases', [])]

            # Fetch KMS key metadata to get the creation date
            key_metadata = kms_client.describe_key(KeyId=key_id)['KeyMetadata']
            creation_date = key_metadata['CreationDate']

            # Fetch CloudTrail events for the specified KMS key
            cloudtrail_client = boto3.client('cloudtrail', region_name=region)
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'ResourceName', 'AttributeValue': key_id},
                    {'AttributeKey': 'EventName', 'AttributeValue': 'Encrypt,Decrypt,GenerateDataKey'},
                ],
            )

            events = response.get('Events', [])

            # Iterate over each event for the KMS key
            for event in events:
                event_time = event.get('EventTime')
                event_name = event.get('EventName')
                username = event.get('Username')
                
                # 'CloudTrailEvent' is a string containing a JSON-formatted CloudTrail event
                cloudtrail_event_str = event.get('CloudTrailEvent', {})
                
                try:
                    # Parse the CloudTrail event string to a JSON object
                    cloudtrail_event = json.loads(cloudtrail_event_str)
                    
                    # Access 'sourceIPAddress' from the CloudTrail event
                    source_ip = cloudtrail_event.get('sourceIPAddress')
                except json.JSONDecodeError as e:
                    print(f"Error decoding CloudTrailEvent JSON: {e}")
                    source_ip = 'N/A'

                # Write details to CSV file
                writer.writerow({
                    'Region': region,
                    'KeyID': key_id,
                    'Aliases': ', '.join(aliases),
                    'EventName': event_name,
                    'LastEventTime': event_time,
                    'Username': username,
                    'SourceIP': source_ip,
                    'CreationDate': creation_date,
                })
