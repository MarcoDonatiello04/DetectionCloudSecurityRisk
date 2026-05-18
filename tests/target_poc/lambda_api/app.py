import json
import sqlite3
import os
import boto3

# Initialize DynamoDB client (configured for LocalStack)
dynamodb = boto3.client(
    'dynamodb',
    endpoint_url=os.environ.get('AWS_ENDPOINT_URL', 'http://localstack:4566'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test'
)

# Initialize S3 client
s3 = boto3.client(
    's3',
    endpoint_url=os.environ.get('AWS_ENDPOINT_URL', 'http://localstack:4566'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test'
)

def build_response(status_code, body):
    # Vulnerabilità: CORS permissivo e mancanza di Security Headers
    return {
        'statusCode': status_code,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Methods': '*'
        },
        'body': json.dumps(body)
    }

def handler(event, context):
    path = event.get('path', '')
    http_method = event.get('httpMethod', '')

    try:
        if path == '/users' and http_method == 'GET':
            # Vulnerabilità: Endpoint senza autenticazione
            return build_response(200, [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}])

        elif path.startswith('/users/') and http_method == 'GET':
            # Vulnerabilità: Nessuna validazione dell'input e SQL/NoSQL Injection simulata
            user_id = path.split('/')[-1]
            # Simuliamo che i dati vengano da una query insicura
            # In un ambiente reale questo potrebbe essere sqlite3.connect().execute("SELECT * FROM users WHERE id = " + user_id)
            return build_response(200, {"id": user_id, "name": f"User_{user_id}", "details": "Found via unsafe query"})

        elif path == '/login' and http_method == 'POST':
            # Vulnerabilità: Fake secrets e Disclosure di errori
            body = json.loads(event.get('body', '{}'))
            if not body.get('username') or not body.get('password'):
                return build_response(400, {"error": "Missing credentials. AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE"})
            return build_response(200, {"token": "fake-jwt-token-12345"})

        elif path == '/admin' and http_method == 'GET':
            # Vulnerabilità: Endpoint admin esposto
            return build_response(200, {
                "message": "Admin Area",
                "db_password": "supersecretpassword123",
                "users_count": 42
            })

        elif path == '/upload' and http_method == 'POST':
            # Vulnerabilità: Upload non validato su bucket pubblico
            body = json.loads(event.get('body', '{}'))
            filename = body.get('filename', 'default.txt')
            content = body.get('content', 'empty content')
            
            s3.put_object(
                Bucket='public-uploads-bucket',
                Key=filename,
                Body=content.encode('utf-8')
            )
            return build_response(200, {"message": f"File {filename} uploaded to public-uploads-bucket"})

        elif path == '/search' and http_method == 'GET':
            # Vulnerabilità: Missing sanitization / Reflected XSS potenziale
            query_params = event.get('queryStringParameters') or {}
            q = query_params.get('q', '')
            return build_response(200, {"results": [], "query": q})

        elif path == '/debug' and http_method == 'GET':
            # Vulnerabilità: Error disclosure e environment dump
            return build_response(200, {
                "env": dict(os.environ),
                "event": event
            })

        elif path == '/notes' and http_method == 'POST':
            # Vulnerabilità: Rate limiting assente
            body = json.loads(event.get('body', '{}'))
            note_id = body.get('id', '1')
            content = body.get('content', 'empty')
            
            dynamodb.put_item(
                TableName='VulnerableNotesTable',
                Item={
                    'id': {'S': note_id},
                    'content': {'S': content}
                }
            )
            return build_response(200, {"message": "Note added successfully"})

        else:
            return build_response(404, {"error": "Not Found"})
            
    except Exception as e:
        # Vulnerabilità: Leak dell'eccezione interna
        return build_response(500, {"error": "Internal Server Error", "details": str(e)})
