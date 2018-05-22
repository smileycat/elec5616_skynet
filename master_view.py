import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

def decrypt_valuables(key,enc_session_key, nonce, tag, ciphertext):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out


    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    try:
        decoded_text = cipher_aes.decrypt_and_verify(ciphertext, tag) #decrypts and validates the MAC address
        print(decoded_text)
    except(ValueError, TypeError):
        print("Decryption failed")        



if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)

    key = RSA.import_key(open(os.path.join("localmaster","private.pem")).read())
    
    f = open(os.path.join("pastebot.net", fn), "rb")
    
    # Reading the encrypted information from file, where 'x' is bytes:
    # First, 256 bytes(size of private key) are used to fetch the encrypted session key
    # Next 16 bytes are used to fetch the aes nonce
    # Next 16 bytes are the MAC tag
    # The rest of the content is the ciphertext
    enc_session_key, nonce, tag, ciphertext = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]

    decrypt_valuables(key, enc_session_key, nonce, tag, ciphertext)
