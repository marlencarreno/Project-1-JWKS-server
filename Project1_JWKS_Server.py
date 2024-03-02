from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request
from uuid import uuid4
import time
import jwt
import traceback
import requests

# Function to generate a unique identifier (kid)
def generate_unique_kid():
    return str(uuid4())

app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Extract public key
public_key = private_key.public_key()

# Associate a key ID (kid) and expiry timestamp with each key
kid = generate_unique_kid()
expiry_timestamp = int(time.time()) + 3600  # Expires in 1 hour

# Serialize public key in PEM format
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Function to issue JWT
def issue_jwt(kid, expired):
    # Set to a timestamp in the past
    claims = {
        'sub': '1234567890',
        'exp': int(time.time()) - 1,  
        'iat': int(time.time()),
        'kid': kid,
        'expired': expired,
    }

    # Serialize private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Create JWT
    token = jwt.encode(claims, pem_private_key, algorithm='RS256', headers={'kid': kid})

    return token
    
# JWKS endpoint
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    try:
        # Implement get_valid_keys to retrieve valid keys
        keys = get_valid_keys()  
        return jsonify({'keys': keys})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# Addinng function to retrieves valid keys
def get_valid_keys():
    global private_key, public_key, kid, expiry_timestamp

    # Verify if the current key has expired
    if int(time.time()) > expiry_timestamp:
        # Regenerate a new key pair and update the kid and expiry_timestamp
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        kid = generate_unique_kid()
        expiry_timestamp = int(time.time()) + 3600  

    # Serialize public key in PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return [{
        'kid': kid,
        'alg': 'RS256',
        'use': 'sig',
        'kty': 'RSA',
        'n': pem_public_key.decode('utf-8').split('\n')[1],  
        'e': 'AQAB',  # Exponent value for RSA key
    }]


# Auth endpoint
@app.route("/auth", methods=["POST"])
def auth():
    try:
        # Issue JWT signed with the private key
        expired = request.args.get('expired')
        # Implement issue_jwt to generate and sign JWT
        token = issue_jwt(kid, expired)  
        return jsonify({'token': token})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# Start server
if __name__ == "__main__":
    app.run(port=8080)
