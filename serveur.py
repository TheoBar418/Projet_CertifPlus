#!/usr/bin/env python3
import os
from bottle import route, run, request, response
from PIL import Image
import qrcode
import zbarlight
import subprocess


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
    with open("temp_data.txt", "w") as f:
        f.write(donnees_texte)
    
    # On cree la requete d'horodatage (.tsq) avec OpenSSL
    subprocess.run(["openssl", "ts", "-query", "-data", "temp_data.txt", "-no_nonce", "-sha256", "-out", "query.tsq"])
    
    # On envoie la requete a FreeTSA avec curl
    subprocess.run(["curl", "-s", "-H", "Content-Type: application/timestamp-query", "--data-binary", "@query.tsq", "https://freetsa.org/tsr", "-o", "response.tsr"])
    
    # On lit la reponse binaire reçue
    with open("response.tsr", "rb") as f:
        timestamp_binaire = f.read()
        
    return timestamp_binaire

def signer_donnees(donnees_texte):
    """
    Signe les donnees avec la cle privee de CertifPlus.
    """
    print("-> Signature cryptographique des donnees...")
    # On s'assure que le fichier temporaire contient bien nos donnees
    with open("temp_data.txt", "w") as f:
        f.write(donnees_texte)
        
    # On demande a OpenSSL de signer le fichier avec notre cle ECC
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", "PKI/ecc.signature.key.pem", "-out", "signature.bin", "temp_data.txt"])
    
    # On recupere la signature generee
    with open("signature.bin", "rb") as f:
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
    
    response.set_header('Content-type', 'text/plain')
    return "L'API a bien recu la demande de creation (en construction...)"

@route('/verification', method='POST')
def verification_attestation():
    # Recuperation de l'image envoyee
    contenu_image = request.files.get('image')
    if contenu_image:
        contenu_image.save('attestation_a_verifier.png', overwrite=True)
        return "Image reçue pour verification (en construction...)"
    return "Erreur : aucune image fournie"

@route('/fond')
def recuperer_fond():
    # Route de test pour verifier que Bottle arrive a lire l'image
    response.set_header('Content-type', 'image/png')
    with open('fond_attestation.png', 'rb') as f:
        return f.read()


# ==========================================
# LANCEMENT DU SERVEUR
# ==========================================

if __name__ == '__main__':
    print("Demarrage du WebService CertifPlus...")
    run(host='0.0.0.0', port=8080, debug=True)