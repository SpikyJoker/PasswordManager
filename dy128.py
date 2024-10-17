#Word is a 4-byte word, and the key is made of 16 bytes/128bits
#The key is expanded into 11 keys of 16 bytes each
ascii_start = 32 #exclusive
ascii_end = 126 #inclusive
freeconfig = { # all values held within can be changed completely freely
    'row_matrix': [3,1,0,2], # the matrix used for the ShiftRows step
    's_box': (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            ),# the substitution box used in each round after shifting bits, I am yet to understand how to make one, so this is taken from github (https://gist.github.com/bonsaiviking/5571001)
    's_box_inv': (
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
            ),  #used in the decryption process, to reverse the substitution box
    'galois_field': [[0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]], # the matrix used for the MixColumns step


    
} 


def xor(a, b):
    '''XORs two values'''
    return a ^ b


class Diffusion():
    '''Spreads out characters within a block, such that a single byte change,\n
    in the initial key or block, will affect more characters in the block:\n
    it will diffuse across bytes and into the entire block'''

    def __init__(self, block:str):
        self.block = block
        self.ShiftRows()
        self.MixColumn()
        #THEN ACCESSED
    
    
    def MixColumn(self):
        '''Takes the column, applies the fixed matrix for free config, and multiplies it by the matrix 
        There are only a finite number of possible values therefore finite field arithmetics are applied

        example: (MixColumns.png)
        
        '''
        # block = self.block
        # for i in range(4):
        #     column = block[i::4]
        pass #to be implemented
    
    def ShiftRows(self):
        '''Shifts the rows of characters in a block'''
        matrix = freeconfig['matrix'] # shift the first row by 0, the second by 1, the third by 3, and the fourth by 2. This can be anything
        block = self.block
        for shift in matrix:
            block = block[shift:] + block[:shift]
        self.block = block
    
    galois_field = freeconfig['galois_field'] #This matrix is absolutely wild and uses some pretty deep maths, that i don't yet fully understand. Luckily, it's already been implemented in the MixColumn function, and it can be freely changed. https://www.youtube.com/watch?v=qGOoDZ100qY
    @staticmethod
    def galois_mult(a, b):
        '''Multiplies two values using the Galois matrix'''
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            a <<= 1 #equivalent to doubling a value
            if a & 0x100: #the fixed field#https://realpython.com/cdn-cgi/image/width=500,format=auto/https://files.realpython.com/media/and.ef7704d02d6f.gif
                a ^= 0x11b #irredubile polynomial (x^8 + x^4 + x^3 + x + 1)
            b >>= 1 #divides b by two
        return p
        # or operator looks like | and does this https://realpython.com/cdn-cgi/image/width=500,format=auto/https://files.realpython.com/media/or.7f09664e2d15.gif
        # xor operator looks like ^ and has been used to implement the galois multiplication
        # the << operator shifts the bits to the left, and the >> operator shifts the bits to the right
        # the = within the bitwise operators is an assignment operator, and the ^= is a compound assignment operator, like +=
        # 0x100 is 256 in hexadecimal, it represents the fixed field, the maximum value
        # 0x11b is the irreducible polynomial, it is used to reduce the value of a, if it exceeds the fixed field
        #0x represents a hexadecimal number, and Bx represents a binary number


class Key():
    def __init__(self,  key = None) -> None:
        if key == None:
            key = self.GenerateKey()
        self.key = key
        self.subkeys = self.GenerateSubkeys()

        class cipher():
            def __init__(self, direction:str, key:str, data:str) -> None:
                self.direction = direction
                self.key = key
                self.subkeys = self.GenerateSubkeys()
                match direction:
                    case 'encrypt':
                        self.Encrypt(data)
                    case 'decrypt':
                        self.Decrypt(data)
                    case _:
                        raise ValueError('Invalid direction')
            
            def Encrypt(self, data:str):
                '''Encrypts data using the dy128 protocol'''
                blocks = self.DataToBlocks(data) # turns data into its blocks
                subkeys = self.KeyExpansion(self.key) # turns key into its subkeys

                encrypted_blocks = []
                for block in blocks:
                    encrypted_block = self.EncryptRound(block, subkeys)
                    encrypted_blocks.append(encrypted_block)

                encrypted_data = self.BlockToData(encrypted_blocks)
                return encrypted_data
            
            def Decrypt(self, data:str):
                '''Decrypts data using the dy128 protocol'''
                pass

            @staticmethod
            def ShiftCharacter(character:str, subkey):
                '''Shifts a single character using a subkey'''
                subkey = bytes(subkey)
                character = bytes(ord(character))

                for offset in subkey:
                    character = character ^ offset
                return character
            
            @staticmethod
            def ShiftCharacter(character:str, subkeys:list):
                shifted_character = character
                for subkey in subkeys:
                    shifted_character = chr(ord(shifted_character) ^ ord(subkey))
                return shifted_character

            @staticmethod
            def DataToBlocks(data:str):
                '''Converts the data into blocks of 16 characters'''
                blocks = []
                for i in range(0, len(data), 16):
                    block = data[i:i+16]
                    blocks.append(block)
                return blocks

            @staticmethod
            def BlockToData(blocks:list):
                '''Converts the blocks into data'''
                data = ''.join(blocks)
                return data

            @staticmethod
            def KeyExpansion(key:str):
                '''Generates subkeys from the master key'''
                subkeys = []
                for i in range(len(key)//4):
                    subkey = key[:i]
                    subkeys.append(subkey)
                return subkeys

            @staticmethod
            def EncryptRound(block:list, subkey):
                '''Encrypts a block of ASCII characters using subkeys'''
                encrypted_block = list()
                for character in block:
                    encrypted_character = cipher.ShiftCharacter(character, subkey)
                    encrypted_block.append(encrypted_character)
                
                diffused = Diffusion(encrypted_block)
                return diffused.block


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