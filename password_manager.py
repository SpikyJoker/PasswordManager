import secrets
from dy128 import cipher
class PasswordHasher():# This class is a placeholder for the argon2-cffi library
    def __init__(self):
        pass

    def hash(text):
        return "hash" + text
    def verify(hash, text):
        return hash == "hash" + text


class Password():
    def __init__(self, text):
        self.text = text
        self.saltgen()
        password = self.hash
        self.password = Encryption.encrypt(password)
    
    def saltgen(self):
        salt = "salt"
        self.salt = secrets.token_bytes(16)   #will be replaced with a random salt of 16 bytes

    def hash(self):
        self. PasswordHasher.hash(self.text + self.salt)





