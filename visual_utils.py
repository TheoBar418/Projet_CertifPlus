from PIL import Image
import subprocess
import qrcode
import zbarlight


# ==========================================
# Visual Generation
# ==========================================

def generate_visual(identity, title, token):
    """
    Creates the final image with text and the signature QR code.
    """
    print("-> Generating the certificate visual...")
    
    # QR code creation (Fixed scale bug by removing it and using standard save)
    qr = qrcode.make(token) 
    qr.save("temp/qrcode.png")

    # Strict resizing to 210x210 pixels
    img_qr = Image.open("temp/qrcode.png")
    img_qr = img_qr.resize((210, 210))
    img_qr.save("temp/qrcode.png")
    
    # Text layer creation with ImageMagick
    text = f"Certificate issued to\n{identity}\n\nfor the certification:\n{title}"
    subprocess.run([
        "convert", "-size", "1000x600", "-gravity", "center", 
        "-pointsize", "48", f"label:{text}", "-transparent", "white", "temp/text.png"
    ], check=True)
    
    # Combining text on the background
    subprocess.run([
        "composite", "-gravity", "center", "temp/text.png", 
        "img/certificate_background.png", "temp/combination.png"
    ], check=True)
    
    # Adding the QR code to the final image
    # Coordinates +1418+934 are given by the assignment
    subprocess.run([
        "composite", "-geometry", "+1418+934", "temp/qrcode.png", 
        "temp/combination.png", "temp/final_certificate.png"
    ], check=True)
    
    print("-> Image 'final_certificate.png' generated successfully!")

def read_qr_code(image_path):
    """
    Uses zbarlight to find and read the QR Code on the image.
    """
    print("-> Reading QR Code...")
    with open(image_path, 'rb') as f:
        image = Image.open(f)
        image.load()
        
    codes = zbarlight.scan_codes(['qrcode'], image)
    if codes:
        return codes[0]
    return None