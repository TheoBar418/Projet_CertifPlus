import subprocess
import datetime
import jwt

# ==========================================
# Cryptography & Timestamping
# ==========================================
def format_information(identity, title):
    """
    Formats the name and title to obtain a 64-character string.
    """
    formatted_string = f"{identity} || {title}"
    # ljust(64) adds spaces at the end until it reaches 64 characters
    return formatted_string.ljust(64)

def get_timestamp(text_data):
    """
    Queries the freetsa.org timestamp authority.
    """
    print("-> Requesting timestamp from FreeTSA...")
    # Write data to a temporary file
    with open("temp/temp_data.txt", "w") as f:
        f.write(text_data)
    
    # Create the timestamp request (.tsq) with OpenSSL
    subprocess.run(["openssl", "ts", "-query", "-data", "temp/temp_data.txt", "-no_nonce", "-sha256", "-out", "temp/query.tsq"])
    
    # Send the request to FreeTSA with curl
    subprocess.run(["curl", "-s", "-H", "Content-Type: application/timestamp-query", "--data-binary", "@temp/query.tsq", "https://freetsa.org/tsr", "-o", "temp/response.tsr"])
    
    # Read the received binary response
    with open("temp/response.tsr", "rb") as f:
        binary_timestamp = f.read()
        
    return binary_timestamp

def sign_data_jwt(identity, title):
    """
    Creates a signed JWT with the ECC private key.
    """
    print("-> Generating JWT...")
    
    # Load private key
    with open("PKI/ecc.signature.key.pem", "rb") as f:
        private_key = f.read()

    # Define the payload
    payload = {
        "iss": "CertifPlus",        # Issuer
        "sub": identity,            # Subject (the student)
        "cert": title,              # The certification
        "iat": datetime.datetime.utcnow(), # Issued at
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365) # Valid for 1 year
    }

    # Create the signed token in ES256 (ECDSA with SHA-256)
    token = jwt.encode(payload, private_key, algorithm="ES256")
    return token

def verify_jwt(token):
    """
    Verifies the JWT with the public key and returns the data if valid.
    """
    print("-> Mathematical verification of the JWT...")
    
    with open("PKI/ecc.signature.pub.pem", "rb") as f:
        public_key = f.read()

    try:
        # The library verifies the signature and expiration date
        decoded = jwt.decode(token, public_key, algorithms=["ES256"])
        return True, decoded
    except jwt.ExpiredSignatureError:
        return False, "The token has expired."
    except jwt.InvalidTokenError:
        return False, "Invalid signature or corrupted token."

