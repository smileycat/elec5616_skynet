import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def sign_file(f,key):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    file_hash = SHA256.new(f)
    signature = pkcs1_15.new(key).sign(file_hash)
    print(signature)
    print("And the rest combined: \n")
    print(signature + b'End Signature\n' + f)
    return signature + b'End Signature\n' + f

def create_rsa_key():
    #creating private key
    key = RSA.generate(2048)
    private_key = key.export_key()
    private_file = open(os.path.join("localmaster","private.pem"), "wb")
    private_file.write(private_key)
    private_file.close()

    #creating public key
    public_key = key.publickey().export_key()
    public_file = open(os.path.join("pastebot.net","public.pem"), "wb")
    public_file.write(public_key)
    public_file.close()

if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    
    if not os.path.exists(os.path.join("localmaster","private.pem")):
        create_rsa_key()
    key = RSA.import_key(open(os.path.join("localmaster","private.pem") ).read() )

    signed_f = sign_file(f,key)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)

