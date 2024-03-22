# Import necessary libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
import time
from memory_profiler import memory_usage
from AES import AES_ENCRYPTION
from RSA import RSA_ENCRYPTION

class HYBRID_ENCRYPTION:
    def __init__(self) -> None:

        self.AES = AES_ENCRYPTION()
        self.RSA = RSA_ENCRYPTION()

    def hash_data(data):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()

    def Encrypt(self, plaintext, aes_key, rsa_public_key):
        iv, ciphertext = self.AES.Encrypt(plaintext, aes_key)
        encrypted_aes_key = self.RSA.Encrypt(rsa_public_key, aes_key)
        return iv, ciphertext, encrypted_aes_key

    def Decrypt(self, iv, ciphertext, encrypted_aes_key, rsa_private_key):
        aes_key = self.RSA.Decrypt(rsa_private_key, encrypted_aes_key)
        decrypted_plaintext = self.AES.Decrypt(ciphertext, aes_key, iv)
        return decrypted_plaintext

    def Time_Usage(self, plainText):

        start_time = time.perf_counter()
        private_key, public_key = self.RSA.GenerateKeys()
        aes_key = self.AES.GenerateKey(32)
        key_generation_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        iv, encrypted_plaintext, encrypted_aes_key = self.Encrypt(plainText, aes_key, public_key)
        encryption_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        decrypted_plaintext = self.Decrypt(iv, encrypted_plaintext, encrypted_aes_key, private_key)
        decryption_time = time.perf_counter() - start_time

        return {'Encrypted_Text':encrypted_plaintext, 'Decrypted_Text':decrypted_plaintext,  'key_generation_time':key_generation_time, 'public_key':public_key, 'private_key':private_key, 'AES_KEY': aes_key, 'encrypted_aes_key':encrypted_aes_key, 'IV':iv, 'encryption_time': encryption_time, 'decryption_time': decryption_time,}
    

    def TIME_MEMORY_USAGE(self, plainText):
        data = self.Time_Usage(plainText)
        encryption_memory = memory_usage((self.Encrypt, (plainText, data['AES_KEY'], data['public_key'])))[0]
        decryption_memory = memory_usage((self.Decrypt, (data['IV'], data['Encrypted_Text'], data['encrypted_aes_key'], data['private_key'])))[0]

        data['encryption_memory'] = str(encryption_memory)+' MB'
        data['decryption_memory'] = str(decryption_memory)+' MB'

        return data


    def SUMMARY(self):

        private_key, public_key = self.RSA.GenerateKeys()
        aes_key = self.AES.GenerateKey(32)

        plaintext = b'Hello, World!'
        iv, ciphertext, encrypted_aes_key = self.Encrypt(plaintext, aes_key, public_key)
        decrypted_plaintext = self.Decrypt(iv, ciphertext, encrypted_aes_key, private_key)

        print("\n####################### Hybrid Solution (AES - RSA) #######################\n")
        print("Original message:", plaintext)
        print("Encrypted Message:", ciphertext)
        print("Decrypted message:", decrypted_plaintext)
        print("")

        data = self.TIME_MEMORY_USAGE(b'Hammad Rafique')
        print(f"Encryption Time: {data['encryption_time']} sec")
        print(f"Decryption Time: {data['decryption_time']} sec")
        print(f"Encryption Memory: {data['encryption_memory']}")
        print(f"Decryption Memory: {data['decryption_memory']}\n\n")


if __name__ == "__main__":

    RSA = RSA_ENCRYPTION()
    AES = AES_ENCRYPTION()
    HYBRID_ENCRYPTION = HYBRID_ENCRYPTION()

    data = HYBRID_ENCRYPTION.TIME_MEMORY_USAGE(b'Hammad Rafique')
    print(data)
    
    
