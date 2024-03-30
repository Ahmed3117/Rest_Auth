

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import zipfile
import os
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from PIL import Image
from io import BytesIO

from users.models import EncodedImage
from ..message.forms import UploadFileForm
from django.shortcuts import render
from django.conf import settings

def generate_aes_key():
    return os.urandom(32)  # 256-bit key

def encrypt_file_aes(file_content, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_content)
    return cipher.nonce, tag, ciphertext

def encrypt_aes_key_rsa(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)

def hybrid_encrypt(file_content, public_key):
    aes_key = generate_aes_key()
    aes_nonce, aes_tag, aes_ciphertext = encrypt_file_aes(file_content, aes_key)
    rsa_encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key)
    return aes_nonce, aes_tag, rsa_encrypted_aes_key, aes_ciphertext

def compress_file(file_content):
    compressed_data = BytesIO()
    with zipfile.ZipFile(compressed_data, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('compressed_file', file_content)
    compressed_data.seek(0)
    return compressed_data.read()

def hide_file(compressed_file, image_path, output_path):
    image_obj = Image.open(image_path)
    encoded_image = image_obj.copy()
    encoded_image.info['compressed_file'] = compressed_file
    encoded_image_io = BytesIO()
    encoded_image.save(encoded_image_io, format='PNG')
    return encoded_image_io.getvalue()

def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            file_content = uploaded_file.read()
            image = request.FILES['image']
            password = form.cleaned_data['password']

            # Perform hybrid encryption
            public_key_path = 'C:/Users/Alarabya/OneDrive/Desktop/grad/project/public_key.pem'
            public_key = RSA.import_key(open(public_key_path, 'rb').read())
            aes_nonce, aes_tag, rsa_encrypted_aes_key, aes_ciphertext = hybrid_encrypt(file_content, public_key)

            # Compress the file content
            compressed_file_content = compress_file(aes_ciphertext)

            # Hide the compressed and encrypted file data into the image
            output_path = f'encoded_image_{request.user.id}.png'
            encoded_image_content = hide_file(compressed_file_content, image, output_path)

            # Save the encoded image to the media directory
            fs = FileSystemStorage(location=settings.MEDIA_ROOT)
            encoded_image_path = fs.save(output_path, ContentFile(encoded_image_content))

            # Create a database entry for the encoded image
            encoded_image_obj = EncodedImage.objects.create(
                user=request.user,
                image=encoded_image_path
            )

            return render(request, 'users/stego_image.html', {'encoded_image_obj': encoded_image_obj})
    else:
        form = UploadFileForm()
    return render(request, 'users/encode.html', {'form': form})











from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import zipfile
import os
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from PIL import Image
from io import BytesIO
import shutil
import tempfile
import mimetypes

from users.models import EncodedImage
from ..message.forms import UploadFileForm
from django.shortcuts import render
from django.conf import settings

def generate_aes_key():
    return os.urandom(32)  # 256-bit key

def encrypt_file_aes(file_content, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_content)
    return cipher.nonce, tag, ciphertext

def encrypt_aes_key_rsa(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)

def hybrid_encrypt(file_content, public_key):
    aes_key = generate_aes_key()
    aes_nonce, aes_tag, aes_ciphertext = encrypt_file_aes(file_content, aes_key)
    rsa_encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key)
    return aes_nonce, aes_tag, rsa_encrypted_aes_key, aes_ciphertext

def hide_file(encrypted_data, image_path):
    image_obj = Image.open(image_path)
    encoded_image = image_obj.copy()
    encoded_image.info['encrypted_data'] = encrypted_data
    encoded_image_io = BytesIO()
    encoded_image.save(encoded_image_io, format='PNG')
    return encoded_image_io.getvalue()

def extract_file_from_image(encoded_image_path, private_key):
    encoded_image = EncodedImage.objects.get(image=encoded_image_path)
    encrypted_data = encoded_image.info['encrypted_data']
    
    aes_key = private_key.decrypt(encrypted_data['rsa_encrypted_aes_key'])
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=encrypted_data['aes_nonce'])
    decrypted_data = cipher.decrypt_and_verify(encrypted_data['aes_ciphertext'], encrypted_data['aes_tag'])
    return decrypted_data

def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            file_content = uploaded_file.read()
            image = request.FILES['image']
            password = form.cleaned_data['password']

            # Perform hybrid encryption
            public_key_path = 'publickey.pem'
            public_key = RSA.import_key(open(public_key_path, 'rb').read())
            aes_nonce, aes_tag, rsa_encrypted_aes_key, aes_ciphertext = hybrid_encrypt(file_content, public_key)

            # Hide the encrypted file data into the image
            encoded_image_content = hide_file({
                'aes_nonce': aes_nonce,
                'aes_tag': aes_tag,
                'rsa_encrypted_aes_key': rsa_encrypted_aes_key,
                'aes_ciphertext': aes_ciphertext
            }, image)

            # Save the encoded image to the media directory
            fs = FileSystemStorage(location=settings.MEDIA_ROOT)
            encoded_image_path = fs.save('encoded_image.png', ContentFile(encoded_image_content))

            # Create a database entry for the encoded image
            encoded_image_obj = EncodedImage.objects.create(
                user=request.user,
                image=encoded_image_path
            )

            return render(request, 'users/stego_image.html', {'encoded_image_obj': encoded_image_obj})
    else:
        form = UploadFileForm()
    return render(request, 'users/encode.html', {'form': form})
def extract(request):
    if request.method == 'POST':
        form = ExtractedFileForm(request.POST, request.FILES)
        if form.is_valid():
            encoded_image = form.cleaned_data['encoded_image']
            password = form.cleaned_data['password']
            
            private_key_path = 'privatekey.pem'
            private_key = RSA.import_key(open(private_key_path, 'rb').read())

            # Validate the uploaded file is an encoded image
            try:
                encoded_image_obj = EncodedImage.objects.get(image=encoded_image)
            except EncodedImage.DoesNotExist:
                form.add_error('encoded_image', 'Invalid file. Please upload a valid encoded image.')
            else:
                # Extract the file from the encoded image
                decrypted_data = extract_file_from_image(encoded_image_obj.image.path, private_key)

                # Create a temporary directory to store the extracted files
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Save the extracted file to the temporary directory
                    extracted_file_path = os.path.join(temp_dir, 'extracted_file.zip')
                    with open(extracted_file_path, 'wb') as extracted_file:
                        extracted_file.write(decrypted_data)

                    # Create an HTTP response with the extracted data
                    with open(extracted_file_path, 'rb') as extracted_file:
                        response = HttpResponse(extracted_file.read(), content_type=mimetypes.guess_type(extracted_file_path)[0])
                        response['Content-Disposition'] = 'attachment; filename="extracted_file.zip"'
                    return response
    else:
        form = ExtractedFileForm()
    return render(request, 'users/decode.html', {'form': form})