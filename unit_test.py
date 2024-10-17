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
if __name__ == '__main__':
    unittest.main()
