from bottle import route, run, request, response, static_file, redirect, HTTPResponse
import urllib.request
import urllib.parse
import re
import os
from dotenv import load_dotenv

# Loads the variables from the .env file into the environment
load_dotenv()

# Retrieves the keys (with a default value)
SECRET_COOKIE = os.getenv("SECRET_COOKIE", "DefaultSecret")


# ==========================================
# Unilim CAS SSO Configuration
# ==========================================
CAS_SERVER = "https://cas.unilim.fr/cas"

@route('/logout')
def logout():
    response.delete_cookie("session_sso", path='/')
    return f"""
        <div style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
            <h2 style="color: #28a745;">Logout successful !</h2>
            <p style="color: #666;"><i>Automatic redirection to the portal...</i></p>
            <script>setTimeout(function() {{ window.location.href = "/"; }}, 2000);</script>
        </div>
        """

# ==========================================
# SECURITY NOTICE: SSO WORKAROUND
# ==========================================
# In a real-world scenario, the application must NEVER handle the user's password directly.
# It should redirect the user to the CAS server, which authenticates them and returns a validation ticket.
# However, because the university's CAS API is restricted and unavailable for student projects,
# this function simulates the authentication flow via web scraping for demonstration purposes.
# DO NOT USE THIS PATTERN IN A PRODUCTION ENVIRONMENT.

@route('/login', method='POST')
def login_sso():
    """
    Integration of the assignment code to validate access via cas.unilim.fr
    """
    username = request.forms.get('username')
    password = request.forms.get('password')

    # ==========================================
    # DEMONSTRATION MODE
    # ==========================================
    if username == "demo" and password == "demo":
        # Simulate cookie creation without querying the CAS
        response.set_cookie("session_sso", username, secret=SECRET_COOKIE, max_age=3600, path='/')
        return f"""
        <div style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
            <h2 style="color: #28a745;">Demonstration authentication successful !</h2>
            <p>Welcome <b>{username}</b> (Mock Mode).</p>
            <p style="color: #666;"><i>Automatic redirection to the portal...</i></p>
            <script>setTimeout(function() {{ window.location.href = "/"; }}, 2000);</script>
        </div>
        """

    # ==========================================
    # ACTUAL UNILIM CAS LOGIN ATTEMPT
    # ==========================================
    try:
        # Retrieve the CSRF token on the CAS homepage
        re_token = re.compile(rb'name="token" value="([^"]+)"')
        req_page = urllib.request.Request('https://cas.unilim.fr')
        rep = urllib.request.urlopen(req_page)
        content = rep.read()
        
        result = re_token.search(content)
        if not result:
            return "ERROR: Unable to retrieve the CAS security token."
        
        token = result.group(1)

        # Attempt connection with the student's credentials
        cookieProcessor = urllib.request.HTTPCookieProcessor()
        opener = urllib.request.build_opener(cookieProcessor)
        
        # We use the username/password variables from the form
        data = urllib.parse.urlencode({
            'user': username, 
            'password': password, 
            'token': token.decode('ascii')
        })
        
        req_login = urllib.request.Request(
            'https://cas.unilim.fr', 
            bytes(data, encoding='ascii')
        )
        
        # Perform the login request
        opener.open(req_login)
        
        # Check for the presence of the 'lemonldap' cookie
        # If this cookie is present, CAS accepted the connection
        cookies = [c for c in cookieProcessor.cookiejar if c.name == 'lemonldap']
        
        if cookies:
            # Success: Create our own session cookie for the application
            response.set_cookie("session_sso", username, secret=SECRET_COOKIE, max_age=3600, path='/' )
            
            # Display success and redirect after 2 seconds
            return f"""
            <div style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
                <h2 style="color: #28a745;">Authentication successful via CAS !</h2>
                <p>Welcome <b>{username}</b>.</p>
                <p style="color: #666;"><i>Automatic redirection to the portal in 2 seconds...</i></p>
                <script>
                    setTimeout(function() {{
                        window.location.href = "/";
                    }}, 2000);
                </script>
            </div>
            """
        else:
            return "FAILURE: Incorrect credentials or TOTP required (off-network)."
    except HTTPResponse:
        raise
    except Exception as e:
        print(f"ERROR: {repr(e)}")
        return f"NETWORK ERROR: Unable to reach the CAS server ({e})"
