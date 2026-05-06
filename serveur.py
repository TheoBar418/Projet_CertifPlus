#!/usr/bin/env python3
import os
from bottle import route, run, request, response
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

def verifier_signature(donnees_texte, signature):
    pass


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

# Pas issue de l'enonce
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


# ==========================================
# Les routes web (Bottle)
# ==========================================

@route('/creation', method='POST')
def creation_attestation():
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
    # Recuperation de l'image envoyee
    contenu_image = request.files.get('image')
    if contenu_image:
        contenu_image.save('temp/attestation_a_verifier.png', overwrite=True)
        return "Image reçue pour verification..."
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