from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
import time
from memory_profiler import memory_usage

class RSA_ENCRYPTION:
    def __init__(self) -> None:
        pass

    def GenerateKeys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def Encrypt(self, public_key, plaintext):
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def Decrypt(self, private_key, ciphertext):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def Time_Usage(self, plainText):
        private_key, public_key = self.GenerateKeys()

        start_time = time.perf_counter()
        encrypted_message = self.Encrypt(public_key, plainText)
        encryption_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        decrypted_message = self.Decrypt(private_key, encrypted_message)
        decrypted_time = time.perf_counter() - start_time

        return {'Encrypted_Text':encrypted_message, 'Decrypted_Text':decrypted_message, 'public_key':public_key, 'private_key':private_key, 'encryption_time': encryption_time, 'decryption_time': decrypted_time}
    

    def TIME_MEMORY_USAGE(self, plainText):
        data = self.Time_Usage(plainText)
        encryption_memory = memory_usage((self.Encrypt, (data['public_key'], plainText)))[0]
        decryption_memory = memory_usage((self.Decrypt, (data['private_key'], data['Encrypted_Text'])))[0]

        data['encryption_memory'] = str(encryption_memory)+' MB'
        data['decryption_memory'] = str(decryption_memory)+' MB'

        return data
    
    def SUMMARY(self):
        plaintext = b'Hammad Rafique'
        private_key, public_key = self.GenerateKeys()
        encrypted_message = self.Encrypt(public_key, plaintext)
        decrypted_message = self.Decrypt(private_key, encrypted_message)

        print("\n####################### RSA #######################\n")
        print(f'RSA Encrypted message: \n{encrypted_message}')
        print(f'Decrypted message: {decrypted_message}\n')

        data = self.TIME_MEMORY_USAGE(b'Hammad Rafique')
        print(f"Encryption Time: {data['encryption_time']} sec")
        print(f"Decryption Time: {data['decryption_time']} sec")
        print(f"Encryption Memory: {data['encryption_memory']}")
        print(f"Decryption Memory: {data['decryption_memory']}\n\n")


if __name__ == "__main__":

    RSA = RSA_ENCRYPTION()

    data = RSA.TIME_MEMORY_USAGE(b'Hammad Rafique')
    print(data)