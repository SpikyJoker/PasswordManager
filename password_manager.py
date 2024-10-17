import secrets
import dy128
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
class Encryption(): #Custom encryption algo Dy256
    def __init__(self):
        pass

    #Break down into blocks
    #blocks are encrypted then diffusion and substitution complicates. 
    #repeat 15 times for each block
    #blocks are then combined and it is converted to hexadecimal

class converter():
    def __init__(self):
        pass
    @classmethod
    def convertBits(cls, bits): #7bits required
        '''Requires at least 7 bits to convert to single ascii character'''
        if isinstance(bits, bytes):
            bits = bits.decode('ascii')
        characters = []
        character_count = len(bits) // 7
        for i in range(character_count):
            ascii = int(bits[i*7:(i+1)*7], 2)
            characters.append(chr(ascii))
        return ''.join(characters)
    @classmethod
    def convertAscii(cls, ascii): #
        for char in ascii:
            bits = bin(ord(char))[2:]



