import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os

# Đảm bảo in ra console với mã hóa UTF-8
sys.stdout.reconfigure(encoding='utf-8')

def get_key_from_password(password):
    # Sử dụng SHA-256 để băm chuỗi khóa thành 32 byte (256 bit)
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(file_name, password):
    key = get_key_from_password(password)
    
    # Đọc dữ liệu từ tệp
    with open(file_name, 'rb') as f:
        plaintext = f.read()

    # Tạo nonce (IV) ngẫu nhiên
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Mã hóa dữ liệu và tạo tag xác thực
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Đặt tên tệp mã hóa
    output_file = os.path.splitext(file_name)[0] + '.enc'

    # Ghi nonce, tag và ciphertext vào tệp mã hóa
    with open(output_file, 'wb') as f:
        f.write(nonce + tag + ciphertext)

    print(f"File '{file_name}' đã được mã hóa thành '{output_file}'.")

def decrypt_file(file_name, password):
    key = get_key_from_password(password)

    # Đọc nonce, tag và ciphertext từ tệp mã hóa
    with open(file_name, 'rb') as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Tạo cipher để giải mã
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Giải mã dữ liệu và xác thực tag
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("Giải mã thất bại hoặc tag không hợp lệ!")
        return

    # Đặt tên tệp đã giải mã
    output_file = os.path.splitext(file_name)[0] + '_decrypted.csv'

    # Ghi dữ liệu đã giải mã vào tệp mới
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"File '{file_name}' đã được giải mã thành '{output_file}'.")

if __name__ == '__main__':
    # Chuỗi khóa do người dùng chọn
    password = "Vpbank@123"

    # Tên tệp cần mã hóa
    original_file = '../board_contents.csv'

    # Mã hóa tệp
    encrypt_file(original_file, password)

    # Giải mã tệp
    encrypted_file = os.path.splitext(original_file)[0] + '.enc'
    decrypt_file(encrypted_file, password)
