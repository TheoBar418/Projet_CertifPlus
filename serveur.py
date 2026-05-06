#!/usr/bin/env python3
import os
from bottle import route, run, request, response
from PIL import Image
import qrcode
import zbarlight


# ==========================================
# Cryptographie & Horodatage
# ==========================================
def obtenir_timestamp():
    pass

def signer_donnees(donnees_texte):
    pass

def verifier_signature(donnees_texte, signature):
    pass


# ==========================================
# Stéganographie (Issue de l'enonce)
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
    
    # Todo
    
    response.set_header('Content-type', 'text/plain')
    return "L'API a bien recu la demande de creation (en construction...)"

@route('/verification', method='POST')
def verification_attestation():
    # Recuperation de l'image envoyee
    contenu_image = request.files.get('image')
    if contenu_image:
        contenu_image.save('attestation_a_verifier.png', overwrite=True)
        return "Image reçue pour vérification (en construction...)"
    return "Erreur : aucune image fournie"

@route('/fond')
def recuperer_fond():
    # Route de test pour verifier que Bottle arrive à lire l'image
    response.set_header('Content-type', 'image/png')
    with open('fond_attestation.png', 'rb') as f:
        return f.read()


# ==========================================
# LANCEMENT DU SERVEUR
# ==========================================

if __name__ == '__main__':
    print("Démarrage du WebService CertifPlus...")
    run(host='0.0.0.0', port=8080, debug=True)