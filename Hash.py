
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import time
from memory_profiler import memory_usage

class HASHING:
    def __init__(self) -> None:
        pass

    def hash_data(self, data):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def Time_Usage(self, plainText):
        start_time = time.perf_counter()
        hashed = self.hash_data(b'Hammad Rafique')
        responeTime = time.perf_counter() - start_time

        return {'Hashed_Text':hashed, 'Decrypted_Text':plainText,  'Hashing_Time':responeTime}
    

    def TIME_MEMORY_USAGE(self, plainText):
        data = self.Time_Usage(plainText)
        hashing_memory = memory_usage((self.hash_data, (plainText,)))[0]
        data['hashing_memory'] = str(hashing_memory)+' MB'
        return data


    def SUMMARY(self):

        print("\n####################### HASHING #######################\n")
        hashed = self.hash_data(b'Hammad Rafique')
        print(f'SHA-256 Hashed data: {hashed}\n')

        data = self.TIME_MEMORY_USAGE(b'Hammad Rafique')
        print(f"Hased Text: {data['Hashed_Text']}")
        print(f"Hashing Time: {data['Hashing_Time']}")
        print(f"Hashing Memory: {data['hashing_memory']}\n\n")

        



if __name__ == "__main__":
    HASHING = HASHING()

    data = HASHING.TIME_MEMORY_USAGE(b'Hammad Rafique')
    print(data)