from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
import time
from memory_profiler import memory_usage

class AES_ENCRYPTION:
    def __init__(self) -> None:
        pass

    def GenerateKey(self, byteInt):
        return os.urandom(byteInt)

    def Encrypt(self, plaintext, key):
        iv = self.GenerateKey(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext
    
    def Decrypt(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()  
        return unpadder.update(decrypted_padded_data) + unpadder.finalize()
    

    def Time_Usage(self, plainText):
        key = self.GenerateKey(32)
        start_time = time.perf_counter()
        iv, encrypted_message = self.Encrypt(plainText, key)
        encryption_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        decrypted_message = self.Decrypt(encrypted_message, key, iv)
        decrypted_time = time.perf_counter() - start_time

        return {'Encrypted_Text':encrypted_message, 'Decrypted_Text':decrypted_message,  'AES_KEY':key, 'IV':iv, 'encryption_time': encryption_time, 'decryption_time': decrypted_time}
    

    def TIME_MEMORY_USAGE(self, plainText):
        data = self.Time_Usage(plainText)
        encryption_memory = memory_usage((self.Encrypt, (plainText, data['AES_KEY'])))[0]
        decryption_memory = memory_usage((self.Decrypt, (data['Encrypted_Text'], data['AES_KEY'], data['IV'])))[0]

        data['encryption_memory'] = str(encryption_memory)+' MB'
        data['decryption_memory'] = str(decryption_memory)+' MB'

        return data

    def SUMMARY(self):
        plaintext = b'Hammad Rafique'
        AES_KEY = self.GenerateKey(32)
        iv, encrypted_message = self.Encrypt(plaintext, AES_KEY)
        decrypted_message = self.Decrypt(encrypted_message, AES_KEY, iv)

        print("\n####################### AES #######################\n")
        print(f'Encrypted message: {encrypted_message}')
        print(f'Decrypted message: {decrypted_message}\n')

        data = self.TIME_MEMORY_USAGE(b'Hammad Rafique')
        print(f"Encryption Time: {data['encryption_time']} sec")
        print(f"Decryption Time: {data['decryption_time']} sec")
        print(f"Encryption Memory: {data['encryption_memory']}")
        print(f"Decryption Memory: {data['decryption_memory']}\n\n")


        
if __name__ == "__main__":
    AES = AES_ENCRYPTION()

    data = AES.TIME_MEMORY_USAGE(b'Hammad Rafique')
    print(data)