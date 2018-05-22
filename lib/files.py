import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master
    key = RSA.import_key(open(os.path.join("pastebot.net","public.pem"), "rb").read())
    session_key = get_random_bytes(16) # session key which will be used to encrypt the data with aes

    #Encrypting the session key with Public RSA encryption
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    #Encrypt the data with AES using the session_key
    cipher_aes = AES.new(session_key,AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data) #encrypt the data and also generate a MAC tag

    return (enc_session_key, cipher_aes.nonce, tag, ciphertext)

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    if not os.path.exists(os.path.join("pastebot.net","public.pem")):
        print("No public key available, uploading stopped.")
        return
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    for encrypted_data in encrypted_master:
        f.write(encrypted_data)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here
    lines = f.split(bytes("End Signature\n", "ascii"), 1)
    if(len(lines) != 2):
        return False
    signature = lines[0] #first line of file
    msg = lines[1] #The message that was sent with the signature.

    #import public key
    if not os.path.exists(os.path.join("pastebot.net","public.pem")):
        print("No public key available")
        return False
    key = RSA.import_key(open(os.path.join("pastebot.net","public.pem"), "rb").read())
    #hash the received message
    msg_hash = SHA256.new(msg)
    try:
        pkcs1_15.new(key).verify(msg_hash,signature)
        return True
    except(ValueError, TypeError):
        return False

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(bytes(fn, 'ascii'))
    sconn.send(bytes(filestore[fn]))

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
