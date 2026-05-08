#!/usr/bin/env python3
import os
from bottle import route, run, request, response, static_file, redirect, HTTPResponse
from PIL import Image
import qrcode
import zbarlight
import subprocess
import base64
import urllib.request
import urllib.parse
import re
import jwt
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CLE_AES_GCM = b"CleSecreteDe32CaracteresPourAES!" # Exactement 32 caracteres

# Creation du dossier temporaire
os.makedirs('temp', exist_ok=True)

# Cle secrete pour chiffrer les cookies de session
SECRET_COOKIE = "LaCleSecreteDeCertifPlus2026"

# ==========================================
# Cryptographie & Horodatage
# ==========================================
def formater_informations(identite, intitule):
    """
    Formate le nom et l'intitule pour obtenir une chaine de 64 caracteres.
    """
    chaine = f"{identite} || {intitule}"
    # ljust(64) rajoute des espaces a la fin jusqu'a atteindre 64 caracteres
    return chaine.ljust(64)

def obtenir_timestamp(donnees_texte):
    """
    Interroge l'autorite d'horodatage freetsa.org.
    """
    print("-> Demande de timestamp a FreeTSA...")
    # On ecrit les donnees dans un fichier temporaire
    with open("temp/temp_data.txt", "w") as f:
        f.write(donnees_texte)
    
    # On cree la requete d'horodatage (.tsq) avec OpenSSL
    subprocess.run(["openssl", "ts", "-query", "-data", "temp/temp_data.txt", "-no_nonce", "-sha256", "-out", "temp/query.tsq"])
    
    # On envoie la requete a FreeTSA avec curl
    subprocess.run(["curl", "-s", "-H", "Content-Type: application/timestamp-query", "--data-binary", "@temp/query.tsq", "https://freetsa.org/tsr", "-o", "temp/response.tsr"])
    
    # On lit la reponse binaire reçue
    with open("temp/response.tsr", "rb") as f:
        timestamp_binaire = f.read()
        
    return timestamp_binaire

def signer_donnees_jwt(identite, intitule):
    """
    Cree un JWT signe avec la cle privee ECC.
    """
    print("-> Generation du JWT...")
    
    # Chargement de la cle privee
    with open("PKI/ecc.signature.key.pem", "rb") as f:
        private_key = f.read()

    # Definition du contenu (Payload)
    payload = {
        "iss": "CertifPlus",        # Emetteur
        "sub": identite,            # Sujet (l'etudiant)
        "cert": intitule,           # La certification
        "iat": datetime.datetime.utcnow(), # Date de creation
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365) # Validite 1 an
    }

    # Creation du jeton signe en ES256 (ECDSA avec SHA-256)
    token = jwt.encode(payload, private_key, algorithm="ES256")
    return token

def verifier_jwt(token):
    """
    Verifie le JWT avec la cle publique et renvoie les donnees si valide.
    """
    print("-> Verification mathematique du JWT...")
    
    with open("PKI/ecc.signature.pub.pem", "rb") as f:
        public_key = f.read()

    try:
        # La bibliotheque verifie la signature et la date d'expiration
        decoded = jwt.decode(token, public_key, algorithms=["ES256"])
        return True, decoded
    except jwt.ExpiredSignatureError:
        return False, "Le jeton a expire."
    except jwt.InvalidTokenError:
        return False, "Signature invalide ou jeton corrompu."

def lire_qr_code(chemin_image):
    """
    Utilise zbarlight pour trouver et lire le QR Code sur l'image.
    """
    print("-> Lecture du QR Code...")
    with open(chemin_image, 'rb') as f:
        image = Image.open(f)
        image.load()
        
    codes = zbarlight.scan_codes(['qrcode'], image)
    if codes:
        return codes[0]
    return None

# ==========================================
# Steganographie
# ==========================================
def vers_8bit(c):
    chaine_binaire = bin(ord(c))[2:]
    return "0"*(8-len(chaine_binaire))+chaine_binaire

def modifier_pixel(pixel, bit):
    r_val = pixel[0]
    rep_binaire = bin(r_val)[2:]
    rep_bin_mod = rep_binaire[:-1] + bit
    r_val = int(rep_bin_mod, 2)
    return tuple([r_val] + list(pixel[1:]))

def cacher_donnees(chemin_image_entree, token_jwt, timestamp_binaire, chemin_sortie):
    print("-> Chiffrement AEAD et Injection steganographique...")
    
    # On prepare les donnees avec un separateur clair (|||)
    donnees_brutes = token_jwt.encode('utf-8') + b'|||' + timestamp_binaire
    
    # Chiffrement AEAD (AES-GCM)
    aesgcm = AESGCM(CLE_AES_GCM)
    nonce = os.urandom(12) # Le nonce doit etre unique (12 octets standards)
    donnees_chiffrees = aesgcm.encrypt(nonce, donnees_brutes, None)
    
    # Le payload final = Nonce + Texte chiffre + Marqueur de fin
    payload_bytes = nonce + donnees_chiffrees + b'===FIN==='
    
    # Conversion en bits et injection 
    bits_a_cacher = ''.join([format(b, '08b') for b in payload_bytes])
    longueur_bits = len(bits_a_cacher)
    
    img = Image.open(chemin_image_entree)
    pixels = img.load()
    largeur, hauteur = img.size
    
    idx_bit = 0
    for y in range(hauteur):
        for x in range(largeur):
            if idx_bit < longueur_bits:
                pixels[x, y] = modifier_pixel(pixels[x, y], bits_a_cacher[idx_bit])
                idx_bit += 1
            else:
                break
        if idx_bit >= longueur_bits:
            break
            
    img.save(chemin_sortie)
    print(f"-> Image steganographiee et chiffree sauvegardee !")

def recuperer_donnees(chemin_image):
    print("-> Extraction et Dechiffrement AEAD en cours...")
    img = Image.open(chemin_image)
    pixels = img.load()
    largeur, hauteur = img.size
    
    bits_extraits = ""
    for y in range(hauteur):
        for x in range(largeur):
            r_val = pixels[x, y][0]
            rep_binaire = bin(r_val)[2:]
            bits_extraits += rep_binaire[-1]
            
    bytes_extraits = bytearray()
    for i in range(0, len(bits_extraits), 8):
        octet = bits_extraits[i:i+8]
        if len(octet) == 8:
            bytes_extraits.append(int(octet, 2))
            
    marqueur = b"===FIN==="
    index_fin = bytes_extraits.find(marqueur)
    
    if index_fin != -1:
        donnees_utiles = bytes_extraits[:index_fin]
        
        # Separation Nonce (12 premiers octets) / Chiffre (Le reste)
        nonce = donnees_utiles[:12]
        donnees_chiffrees = donnees_utiles[12:]
        
        # Dechiffrement AEAD (Garantit la confidentialite ET l'integrite)
        try:
            aesgcm = AESGCM(CLE_AES_GCM)
            donnees_decryptees = aesgcm.decrypt(nonce, donnees_chiffrees, None)
        except Exception as e:
            print("Echec du dechiffrement AEAD (Mot de passe invalide ou alteration !)")
            return None, None

        # Separation JWT / Timestamp via notre separateur
        parties = donnees_decryptees.split(b'|||', 1)
        if len(parties) == 2:
            token_jwt = parties[0].decode('utf-8')
            timestamp_binaire = parties[1]
            return token_jwt, timestamp_binaire
            
    return None, None


# ==========================================
# Configuration du SSO CAS Unilim
# ==========================================
CAS_SERVER = "https://cas.unilim.fr/cas"

@route('/logout')
def logout():
    response.delete_cookie("session_sso", path='/')
@route('/login', method='POST')
def login_sso():
    """
    Integration du code de l'enonce pour valider l'acces via cas.unilim.fr
    """
    username = request.forms.get('username')
    password = request.forms.get('password')

    try:
        # Recuperation du token CSRF sur la page d'accueil du CAS
        re_token = re.compile(rb'name="token" value="([^"]+)"')
        req_page = urllib.request.Request('https://cas.unilim.fr')
        rep = urllib.request.urlopen(req_page)
        contenu = rep.read()
        
        resultat = re_token.search(contenu)
        if not resultat:
            return "ERREUR : Impossible de recuperer le token de securite du CAS."
        
        token = resultat.group(1)

        # Tentative de connexion avec les identifiants de l'etudiant
        cookieProcessor = urllib.request.HTTPCookieProcessor()
        opener = urllib.request.build_opener(cookieProcessor)
        
        # On utilise les variables username/password du formulaire
        data = urllib.parse.urlencode({
            'user': username, 
            'password': password, 
            'token': token.decode('ascii')
        })
        
        req_login = urllib.request.Request(
            'https://cas.unilim.fr', 
            bytes(data, encoding='ascii')
        )
        
        # On effectue la requete de login
        opener.open(req_login)
        
        # Verification de la presence du cookie 'lemonldap'
        # Si ce cookie est present, c'est que le CAS a accepte la connexion
        cookies = [c for c in cookieProcessor.cookiejar if c.name == 'lemonldap']
        
        if cookies:
            # Succes : On cree notre propre cookie de session pour l'application
            response.set_cookie("session_sso", username, secret=SECRET_COOKIE, max_age=3600, path='/' )
            
            # On affiche le succes et on redirige apres 2 secondes 
            return f"""
            <div style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
                <h2 style="color: #28a745;">Authentification reussie via CAS !</h2>
                <p>Bienvenue <b>{username}</b>.</p>
                <p style="color: #666;"><i>Redirection automatique vers le portail dans 2 secondes...</i></p>
                <script>
                    setTimeout(function() {{
                        window.location.href = "/";
                    }}, 2000);
                </script>
            </div>
            """
        else:
            return "ECHEC : Identifiants incorrects ou TOTP requis (hors reseau)."
    except HTTPResponse :
        raise
    except Exception as e:
        print(f"ERREUR : {repr(e)}")
        return f"ERREUR ReSEAU : Impossible de joindre le serveur CAS ({e})"


# ==========================================
# Les routes web (Bottle)
# ==========================================

@route('/', method='GET')
def index():
    """
    Affiche la page d'accueil web.
    """
    return static_file('index.html', root='.')

@route('/creation', method='POST')
def creation_attestation():
    utilisateur = request.get_cookie("session_sso", secret=SECRET_COOKIE)
    if not utilisateur:
        return "ACCES REFUSE : Vous devez d'abord vous connecter !"

    identite = request.forms.get('identite')
    intitule = request.forms.get('intitule_certif')
    print(f"\n--- NOUVELLE DEMANDE (JWT + AEAD) : {identite} ---")

    # Generation du JWT
    token_jwt = signer_donnees_jwt(identite, intitule)
    
    # Horodatage externe
    timestamp = obtenir_timestamp(token_jwt)

    # Generation visuelle avec QR Code
    generer_visuel(identite, intitule, token_jwt)    

    # Steganographie chiffree
    cacher_donnees('temp/attestation_finale.png', token_jwt, timestamp, 'temp/attestation_securisee.png')    
    
    response.set_header('Content-type', 'image/png')
    response.set_header('Content-Disposition', 'attachment; filename="diplome_certifplus.png"') 
    with open('temp/attestation_securisee.png', 'rb') as f:
        return f.read()

@route('/verification', method='POST')
def verification_attestation():
    print("\n--- VERIFICATION DE DIPLOME ---")
    contenu_image = request.files.get('image')
    
    if contenu_image:
        chemin_image = 'temp/attestation_a_verifier.png'
        contenu_image.save(chemin_image, overwrite=True)
        
        # Lecture du JWT depuis le QR Code
        token_qr_bytes = lire_qr_code(chemin_image)
        if not token_qr_bytes:
            return "ERREUR : Impossible de lire le QR code."
        token_qr = token_qr_bytes.decode('utf-8')
            
        # Extraction steganographique et dechiffrement AEAD
        token_stego, timestamp = recuperer_donnees(chemin_image)
        if not token_stego:
            return "ERREUR : Donnees cachees introuvables ou alterees (AEAD Check failed)."
            
        # Comparaison
        if token_qr != token_stego:
            return "ALERTE FRAUDE : Le QR Code et les pixels caches ne correspondent pas !"

        # Verification de la signature cryptographique du JWT
        succes, payload = verifier_jwt(token_qr)
        
        if succes:
            return f"SUCCES : Diplome authentique ! Emis pour {payload.get('sub')} ({payload.get('cert')})."
        else:
            return f"ALERTE FRAUDE : Jeton invalide ou expire ({payload})."
            
    return "Erreur : aucune image fournie"

@route('/fond')
def recuperer_fond():
    # Route de test pour verifier que Bottle arrive a lire l'image
    response.set_header('Content-type', 'image/png')
    with open('img/fond_attestation.png', 'rb') as f:
        return f.read()


# ==========================================
# Generation visuelle
# ==========================================

def generer_visuel(identite, intitule, token):
    """
    Cree l'image finale avec le texte et le QR code de la signature.
    """
    print("-> Generation du visuel de l'attestation...")
    
    # Creation du QR code
    qr = qrcode.make(token) 
    qr.save("temp/qrcode.png", scale="2")

    # Redimensionnement strict a 210x210 pixels
    img_qr = Image.open("temp/qrcode.png")
    img_qr = img_qr.resize((210, 210))
    img_qr.save("temp/qrcode.png")
    
    # Creation du calque de texte avec ImageMagick
    texte = f"Certificat delivre a\n{identite}\n\npour la certification :\n{intitule}"
    subprocess.run([
        "convert", "-size", "1000x600", "-gravity", "center", 
        "-pointsize", "48", f"label:{texte}", "-transparent", "white", "temp/texte.png"
    ])
    
    # Combinaison du texte sur le fond
    subprocess.run([
        "composite", "-gravity", "center", "temp/texte.png", 
        "img/fond_attestation.png", "temp/combinaison.png"
    ])
    
    # Ajout du QR code sur l'image finale
    # Les coordonnees +1418+934 sont donnees par l'enonce
    subprocess.run([
        "composite", "-geometry", "+1418+934", "temp/qrcode.png", 
        "temp/combinaison.png", "temp/attestation_finale.png"
    ])
    
    print("-> Image 'attestation_finale.png' generee avec succes !")


# ==========================================
# LANCEMENT DU SERVEUR
# ==========================================

if __name__ == '__main__':
    print("Demarrage du WebService CertifPlus...")
    run(host='0.0.0.0', port=8080, debug=True)