from password_manager import *
import unittest

class TestStringMethods(unittest.TestCase):
    def test_conversion(self):  # Updated method name to start with "test_"
        converter_instance = converter()
                
        byte_equivalent = bytes("1110000", 'ascii')
        a = converter_instance.convertBits(byte_equivalent)
        b = converter_instance.convertAscii("p")

        self.assertEqual(a, "p")
        self.assertEqual(b, "1110000")  # Updated assertions for clarity
    def test_password(self):
        password_instance = Password.create("password")
        self.assertEqual(password_instance.text, "password")
        self.assertEqual(password_instance.salt, "salt")
    def test_encryption(self):
        '''Tests the dy256 protocol'''
        data = 'Cain kills Abel.' # 16 character string
        key = 'OvDRX%<1[}s[y6E+' # generated at https://catonmat.net/tools/generate-random-ascii
        encrypted_message = dy128.Encrypt(data, key)
        self.assertNotEqual(encrypted_message, data)
        decrypted_message = dy128.Decrypt(encrypted_message, key)
        self.assertEqual(decrypted_message, data)
    
if __name__ == '__main__':
    unittest.main()
