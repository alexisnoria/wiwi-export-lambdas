import json
import boto3
import os
import datetime

def login(event, context):
    try:
        body = json.loads(event.get('body', '{}'))
        username = body.get('username')
        password = body.get('password')
        
        if not username or not password:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Username and password are required"})
            }
            
        client_id = os.environ.get('COGNITO_CLIENT_ID')
        if not client_id:
             return {
                "statusCode": 500,
                "body": json.dumps({"message": "Server configuration error: COGNITO_CLIENT_ID not set"})
            }

        client = boto3.client('cognito-idp')
        
        response = client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        
        # Check if there's a challenge (e.g., NEW_PASSWORD_REQUIRED)
        if 'ChallengeName' in response:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Challenge required",
                    "challenge": response['ChallengeName'],
                    "session": response.get('Session'),
                    "challenge_parameters": response.get('ChallengeParameters', {})
                })
            }
        
        # Normal successful authentication
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Login successful",
                "auth_result": response['AuthenticationResult']
            })
        }
        
    except client.exceptions.NotAuthorizedException:
        return {
            "statusCode": 401,
            "body": json.dumps({"message": "Incorrect username or password"})
        }
    except client.exceptions.UserNotFoundException:
        return {
            "statusCode": 404,
            "body": json.dumps({"message": "User not found"})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": f"Login failed: {str(e)}"})
        }

def change_password(event, context):
    try:
        body = json.loads(event.get('body', '{}'))
        username = body.get('username')
        session = body.get('session')
        new_password = body.get('new_password')
        
        if not username or not session or not new_password:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Username, session, and new_password are required"})
            }
            
        client_id = os.environ.get('COGNITO_CLIENT_ID')
        if not client_id:
            return {
                "statusCode": 500,
                "body": json.dumps({"message": "Server configuration error: COGNITO_CLIENT_ID not set"})
            }

        client = boto3.client('cognito-idp')
        
        response = client.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName='NEW_PASSWORD_REQUIRED',
            Session=session,
            ChallengeResponses={
                'USERNAME': username,
                'NEW_PASSWORD': new_password
            }
        )
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Password changed successfully",
                "auth_result": response['AuthenticationResult']
            })
        }
        
    except client.exceptions.InvalidPasswordException as e:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": f"Invalid password: {str(e)}"})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": f"Password change failed: {str(e)}"})
        }


def get_latest_csv(bucket_name):
    s3 = boto3.client('s3')
    response = s3.list_objects_v2(Bucket=bucket_name)
    
    if 'Contents' not in response:
        return None
        
    csv_files = [
        obj for obj in response['Contents'] 
        if obj['Key'].lower().endswith('.csv')
    ]
    
    if not csv_files:
        return None
        
    # Sort by LastModified descending
    latest_file = sorted(
        csv_files, 
        key=lambda x: x['LastModified'],
        
        reverse=True
    )[0]
    
    return latest_file['Key']
def hello(event, context):
    # Audit logging
    try:
        table_name = os.environ.get('AUDIT_TABLE_NAME')
        if table_name:
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table(table_name)
            
            # Extract user info from JWT claims
            claims = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {})
            user_email = claims.get('email', 'unknown')
            user_sub = claims.get('sub', 'unknown')
            
            # Extract IP address
            source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')
            
            table.put_item(
                Item={
                    'requestId': context.aws_request_id,
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'userEmail': user_email,
                    'userId': user_sub,
                    'sourceIp': source_ip,
                    'action': 'download_csv'
                }
            )
    except Exception as e:
        print(f"Audit logging failed: {str(e)}")

    bucket_name = "export-data-qa6nwc27gv"
    bucket_name = "export-data-qa6nwc27gv"
    
    try:
        latest_file_key = get_latest_csv(bucket_name)
        
        if not latest_file_key:
            return {
                "statusCode": 404,
                "body": json.dumps({"message": "No CSV files found."})
            }

        s3 = boto3.client('s3')
        file_obj = s3.get_object(Bucket=bucket_name, Key=latest_file_key)
        content = file_obj['Body'].read().decode('utf-8')
        
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "text/csv",
                "Content-Disposition": f'attachment; filename="{latest_file_key}"'
            },
            "body": content
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": f"Error retrieving file: {str(e)}"})
        }
