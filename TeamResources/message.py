from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Load private key from file
with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# Load encrypted message from file
with open("final_message.enc", "rb") as f:
    encrypted = f.read()

# Set up cipher for decryption
cipher_decrypt = PKCS1_OAEP.new(private_key)

# Decrypt the message
decrypted = cipher_decrypt.decrypt(encrypted)
print("Decrypted message:")
print(decrypted.decode())