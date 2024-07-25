from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
import os

def encrypt_message(message, password):
    # Generate a key from the password
    salt = os.urandom(16)  # 16 bytes salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Pad the message to be a multiple of the block size (AES block size is 128 bits)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return salt + iv + encrypted_message

def decrypt_message(encrypted_message, password):
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]

    # Derive the key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the message
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return decrypted_message.decode()

def encode_image(image_path, message, password, output_path):
    encrypted_message = encrypt_message(message, password)
    message_bits = ''.join(format(byte, '08b') for byte in encrypted_message)

    image = Image.open(image_path)
    encoded_image = image.copy()
    width, height = image.size

    index = 0
    for y in range(height):
        for x in range(width):
            pixel = list(image.getpixel((x, y)))
            for n in range(3):
                if index < len(message_bits):
                    pixel[n] = (pixel[n] & 0xFE) | int(message_bits[index])
                    index += 1
                if index >= len(message_bits):
                    break
            encoded_image.putpixel((x, y), tuple(pixel))
        if index >= len(message_bits):
            break

    encoded_image.save(output_path)
    return output_path

def decode_image(image_path, password):
    image = Image.open(image_path)
    width, height = image.size

    message_bits = ""
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            for n in range(3):
                message_bits += str(pixel[n] & 1)

    message_bytes = bytearray()
    for i in range(0, len(message_bits), 8):
        byte = message_bits[i:i+8]
        if len(byte) == 8:
            message_bytes.append(int(byte, 2))

    try:
        decrypted_message = decrypt_message(bytes(message_bytes), password)
        return decrypted_message
    except Exception as e:
        print("Decryption failed. Incorrect password or corrupted data.")
        return None

# Example usage:
if __name__ == "__main__":
    image_path = 'input_image.png'
    message = 'Secret message'
    password = 'securepassword'
    output_path = 'encoded_image.png'

    # Encode the message in the image
    encoded_image_path = encode_image(image_path, message, password, output_path)
    print(f"Message encoded and saved to {encoded_image_path}")

    # Decode the message from the image
    decoded_message = decode_image(encoded_image_path, password)
    if decoded_message:
        print(f"Decoded message: {decoded_message}")
    else:
        print("Failed to decode the message.")
