import os
from bottle import route, run, request, response, static_file, redirect, HTTPResponse
from crypto_utils import sign_data_jwt, get_timestamp, verify_jwt
from stego_utils import hide_data, extract_data
from visual_utils import generate_visual, read_qr_code
import auth_sso
from dotenv import load_dotenv

# Creation of the temporary directory
os.makedirs('temp', exist_ok=True)

# Loads the variables from the .env file into the environment
load_dotenv()

# Retrieves the keys (with a default value)
SECRET_COOKIE = os.getenv("SECRET_COOKIE", "DefaultSecret")


# ==========================================
# Web Routes (Bottle)
# ==========================================

@route('/', method='GET')
def index():
    """
    Displays the web homepage.
    """
    return static_file('index.html', root='.')

@route('/creation', method='POST')
def create_certificate():
    user = request.get_cookie("session_sso", secret=SECRET_COOKIE)
    if not user:
        return "ACCESS DENIED: You must log in first!"

    identity = request.forms.get('identity')
    title = request.forms.get('certif_title')
    print(f"\n--- NEW REQUEST (JWT + AEAD) : {identity} ---")

    # JWT Generation
    jwt_token = sign_data_jwt(identity, title)
    
    # External timestamping
    timestamp = get_timestamp(jwt_token)

    # Visual generation with QR Code
    generate_visual(identity, title, jwt_token)    

    # Encrypted steganography
    hide_data('temp/final_certificate.png', jwt_token, timestamp, 'temp/secured_certificate.png')    
    
    response.set_header('Content-type', 'image/png')
    response.set_header('Content-Disposition', 'attachment; filename="certifplus_diploma.png"') 
    with open('temp/secured_certificate.png', 'rb') as f:
        return f.read()

@route('/verification', method='POST')
def verify_certificate():
    print("\n--- DIPLOMA VERIFICATION ---")
    image_content = request.files.get('image')
    
    if image_content:
        image_path = 'temp/certificate_to_verify.png'
        image_content.save(image_path, overwrite=True)
        
        # Read the JWT from the QR Code
        qr_token_bytes = read_qr_code(image_path)
        if not qr_token_bytes:
            return "ERROR: Unable to read the QR code."
        qr_token = qr_token_bytes.decode('utf-8')
            
        # Steganographic extraction and AEAD decryption
        stego_token, timestamp = extract_data(image_path)
        if not stego_token:
            return "ERROR: Hidden data not found or altered (AEAD Check failed)."
            
        # Comparison
        if qr_token != stego_token:
            return "FRAUD ALERT: The QR Code and the hidden pixels do not match!"

        # Cryptographic signature verification of the JWT
        success, payload = verify_jwt(qr_token)
        
        if success:
            return f"SUCCESS: Authentic diploma! Issued to {payload.get('sub')} ({payload.get('cert')})."
        else:
            return f"FRAUD ALERT: Invalid or expired token ({payload})."
            
    return "Error: no image provided"

@route('/background')
def get_background():
    # Test route to verify that Bottle can read the image
    response.set_header('Content-type', 'image/png')
    with open('img/certificate_background.png', 'rb') as f:
        return f.read()


# ==========================================
# SERVER LAUNCH
# ==========================================

if __name__ == '__main__':
    print("Starting the CertifPlus WebService...")
    run(host='0.0.0.0', port=8080, debug=True)