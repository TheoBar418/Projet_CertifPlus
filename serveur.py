#!/usr/bin/env python3
import os
from bottle import route, run, request, response, static_file
from PIL import Image
import qrcode
import zbarlight
import subprocess
import base64


# Creation du dossier temporaire
os.makedirs('temp', exist_ok=True)


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

def signer_donnees(donnees_texte):
    """
    Signe les donnees avec la cle privee de CertifPlus.
    """
    print("-> Signature cryptographique des donnees...")
    # On s'assure que le fichier temporaire contient bien nos donnees
    with open("temp/temp_data.txt", "w") as f:
        f.write(donnees_texte)
        
    # On demande a OpenSSL de signer le fichier avec notre cle ECC
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", "PKI/ecc.signature.key.pem", "-out", "temp/signature.bin", "temp/temp_data.txt"])
    
    # On recupere la signature generee
    with open("temp/signature.bin", "rb") as f:
        signature_binaire = f.read()
        
    return signature_binaire

def verifier_signature(donnees_texte, signature_binaire):
    """
    Demande à OpenSSL de vérifier mathematiquement la signature.
    """
    print("-> Verification de la signature avec la cle publique...")
    
    # On recrée les fichiers temporaires pour OpenSSL
    with open("temp/verif_data.txt", "w") as f:
        f.write(donnees_texte)
    with open("temp/verif_sig.bin", "wb") as f:
        f.write(signature_binaire)
        
    # On lance la vérification avec la cle publique
    resultat = subprocess.run([
        "openssl", "dgst", "-sha256", "-verify", "PKI/ecc.signature.pub.pem", 
        "-signature", "temp/verif_sig.bin", "temp/verif_data.txt"
    ], capture_output=True, text=True)
    
    # OpenSSL renvoie "Verified OK" si tout est bon
    if "Verified OK" in resultat.stdout:
        return True
    return False

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
        # Le QR Code contient de l'ASCII (Base64), on le retransforme en binaire
        signature_binaire = base64.b64decode(codes[0])
        return signature_binaire
    return None


# ==========================================
# Steganographie (Issue de l'enonce)
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


# ==========================================
# Pas issue de l'enonce
# ==========================================
def cacher_donnees(chemin_image_entree, donnees_texte, timestamp_binaire, chemin_sortie):
    print("-> Injection steganographique en cours...")
    
    # Preparation du "Payload" qu'on va cacher
    # On colle les donnees (converties en bytes) avec le timestamp, et un marqueur de fin
    payload_bytes = donnees_texte.encode('utf-8') + timestamp_binaire + b'===FIN==='
    
    # Conversion de tout ce bloc en une immense chaine de '0' et de '1'
    bits_a_cacher = ''.join([format(b, '08b') for b in payload_bytes])
    longueur_bits = len(bits_a_cacher)
    
    # Ouverture de l'image
    img = Image.open(chemin_image_entree)
    pixels = img.load()
    largeur, hauteur = img.size
    
    idx_bit = 0
    
    # On parcourt les pixels un par un pour cacher les bits
    for y in range(hauteur):
        for x in range(largeur):
            if idx_bit < longueur_bits:
                pixels[x, y] = modifier_pixel(pixels[x, y], bits_a_cacher[idx_bit])
                idx_bit += 1
            else:
                break # On a tout cache, on sort de la boucle !
        if idx_bit >= longueur_bits:
            break
            
    # Sauvegarde de l'image finale
    img.save(chemin_sortie)
    print(f"-> Image steganographiee sauvegardee sous : {chemin_sortie}")

def recuperer_donnees(chemin_image):
    """
    Lit les pixels de l'image pour retrouver les données cachées.
    """
    print("-> Extraction stéganographique en cours...")
    img = Image.open(chemin_image)
    pixels = img.load()
    largeur, hauteur = img.size
    
    bits_extraits = ""
    # On parcourt tous les pixels pour recuperer le dernier bit rouge
    for y in range(hauteur):
        for x in range(largeur):
            r_val = pixels[x, y][0]
            rep_binaire = bin(r_val)[2:]
            bits_extraits += rep_binaire[-1]
            
    # On regroupe les bits par 8 pour refaire des octets (bytes)
    bytes_extraits = bytearray()
    for i in range(0, len(bits_extraits), 8):
        octet = bits_extraits[i:i+8]
        if len(octet) == 8:
            bytes_extraits.append(int(octet, 2))
            
    # On cherche notre fameux marqueur de fin pour arrêter de lire du "bruit"
    marqueur = b"===FIN==="
    index_fin = bytes_extraits.find(marqueur)
    
    if index_fin != -1:
        donnees_utiles = bytes_extraits[:index_fin]
        # Les 64 premiers octets sont le texte, le reste c'est le timestamp 
        donnees_texte = donnees_utiles[:64].decode('utf-8')
        timestamp_binaire = donnees_utiles[64:]
        return donnees_texte, timestamp_binaire
        
    return None, None 


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
    print("\n--- NOUVELLE DEMANDE DE CREATION ---")
    # Recuperation des donnees envoyees
    identite = request.forms.get('identite')
    intitule = request.forms.get('intitule_certif')
    print(f"Demande reçue pour : {identite} - {intitule}")

    # Formatage a 64 caracteres
    donnees_64 = formater_informations(identite, intitule)
    print(f"Donnees formatees ({len(donnees_64)} caracteres) : '{donnees_64}'")

    # Obtention du Timestamp
    timestamp = obtenir_timestamp(donnees_64)
    print(f"Timestamp reçu (Taille: {len(timestamp)} octets)")

    # Signature
    signature = signer_donnees(donnees_64)
    print(f"Signature generee (Taille: {len(signature)} octets)")

    # Generation de l'image
    generer_visuel(identite, intitule, signature)
    
    # Steganographie : On cache les donnees dans l'image finale
    cacher_donnees('temp/attestation_finale.png', donnees_64, timestamp, 'temp/attestation_securisee.png')
    
    # On renvoie l'image securisee au client qui a fait la requete
    response.set_header('Content-type', 'image/png')
    # Force le navigateur/curl à telecharger le fichier sous un beau nom
    response.set_header('Content-Disposition', 'attachment; filename="diplome_certifplus.png"') 
    
    with open('temp/attestation_securisee.png', 'rb') as f:
        return f.read()

@route('/verification', method='POST')
def verification_attestation():
    print("\n--- NOUVELLE DEMANDE DE VERIFICATION ---")
    contenu_image = request.files.get('image')
    
    if contenu_image:
        chemin_image = 'temp/attestation_a_verifier.png'
        contenu_image.save(chemin_image, overwrite=True)
        
        # Extraction Steganographique
        donnees_texte, timestamp = recuperer_donnees(chemin_image)
        if not donnees_texte:
            return "ERREUR : Aucune donnee steganographique trouvee. L'image a ete alteree ou n'est pas un diplome CertifPlus."
            
        print(f"Donnees extraites : '{donnees_texte}'")
        
        # Lecture du QR Code
        signature = lire_qr_code(chemin_image)
        if not signature:
            return "ERREUR : Impossible de lire le QR code."
            
        # Verification mathematique
        est_valide = verifier_signature(donnees_texte, signature)
        
        if est_valide:
            return f"SUCCES : Le diplome est authentique et mathematiquement valide !\nIl a ete delivre pour : {donnees_texte.strip()}"
        else:
            return "ALERTE FRAUDE : La signature cryptographique est invalide. Le texte ou l'image a ete modifie !"
            
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

def generer_visuel(identite, intitule, signature_binaire):
    """
    Cree l'image finale avec le texte et le QR code de la signature.
    """
    print("-> Generation du visuel de l'attestation...")
    
    # Conversion de la signature en ASCII (Base64) pour le QR code
    signature_ascii = base64.b64encode(signature_binaire).decode('utf-8')
    
    # Creation du QR code
    qr = qrcode.make(signature_ascii)
    qr.save("temp/qrcode.png", scale=2)

    # Redimensionnement strict à 210x210 pixels
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