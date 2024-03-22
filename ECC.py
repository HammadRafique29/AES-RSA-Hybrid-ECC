from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time
from memory_profiler import memory_usage

class ECC_ENCRYPTION:
    def __init__(self) -> None:
        pass

    def GenerateKeys(self):
        private_key = ec.generate_private_key(
            ec.SECP384R1(),
            default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    # def Encrypt(self, private_key, public_key, plaintext):
    #     shared_key = private_key.exchange(ec.ECDH(), public_key)
    #     kdf = HKDF(
    #         algorithm=hashes.SHA256(),
    #         length=32,
    #         salt=None,
    #         info=None,
    #         backend=default_backend()
    #     )
    #     key = kdf.derive(shared_key)
    #     cipher = Cipher(algorithms.AES(key), modes.CTR(nonce=os.urandom(16)), default_backend())
    #     encryptor = cipher.encryptor()
    #     ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    #     return ciphertext
    
    def Encrypt(self, private_key, public_key, plaintext):
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        )
        key = kdf.derive(shared_key)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce, ciphertext

    # def Decrypt(self, private_key, public_key, ciphertext):
    #     shared_key = private_key.exchange(ec.ECDH(), public_key)
    #     kdf = HKDF(
    #         algorithm=hashes.SHA256(),
    #         length=32,
    #         salt=None,
    #         info=None,
    #         backend=default_backend()
    #     )
    #     key = kdf.derive(shared_key)
    #     cipher = Cipher(algorithms.AES(key), modes.CTR(nonce=os.urandom(16)), default_backend())
    #     decryptor = cipher.decryptor()
    #     plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    #     return plaintext

    def Decrypt(self, private_key, public_key, nonce, ciphertext):
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        )
        key = kdf.derive(shared_key)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def Time_Usage(self, plainText):
        private_key, public_key = self.GenerateKeys()

        start_time = time.perf_counter()
        nonce, encrypted_message = self.Encrypt(private_key=private_key, public_key=public_key, plaintext=plainText)
        encryption_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        decrypted_message = self.Decrypt(private_key, public_key, nonce, encrypted_message)
        decryption_time = time.perf_counter() - start_time

        return {'Encrypted_Text':encrypted_message, 'nonce':nonce , 'Decrypted_Text':decrypted_message, 'public_key':public_key, 'private_key':private_key, 'encryption_time': encryption_time, 'decryption_time': decryption_time}
    
    def TIME_MEMORY_USAGE(self, plainText):
        data = self.Time_Usage(plainText)
        encryption_memory = memory_usage((self.Encrypt, (data['private_key'], data['public_key'], plainText)))[0]
        decryption_memory = memory_usage((self.Decrypt, (data['private_key'], data['public_key'], data['nonce'], data['Encrypted_Text'])))[0]

        data['encryption_memory'] = str(encryption_memory)+' MB'
        data['decryption_memory'] = str(decryption_memory)+' MB'

        return data
    
    def SUMMARY(self):
        plaintext = b'Hammad Rafique'
        private_key, public_key = self.GenerateKeys()
        nonce, encrypted_message = self.Encrypt(private_key=private_key, public_key=public_key, plaintext=plaintext)
        decrypted_message = self.Decrypt(private_key, public_key, nonce, encrypted_message).decode()

        print("\n####################### ECC #######################\n")
        print(f'ECC Encrypted message: \n{encrypted_message}')
        print(f'Decrypted message: {decrypted_message}\n')

        data = self.TIME_MEMORY_USAGE(b'Hammad Rafique')
        print(f"Encryption Time: {data['encryption_time']} sec")
        print(f"Decryption Time: {data['decryption_time']} sec")
        print(f"Encryption Memory: {data['encryption_memory']}")
        print(f"Decryption Memory: {data['decryption_memory']}\n\n")

if __name__ == "__main__":
    ECC = ECC_ENCRYPTION()

    ECC.SUMMARY()
    # data = ECC.TIME_MEMORY_USAGE(b'Hammad Rafique')
    # print(data)