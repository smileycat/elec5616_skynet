import struct
import base64


from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from dh import create_dh_key, calculate_dh_secret

BLOCK_SIZE = 16  # Bytes

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = ""
        self.initiate_session()
 
    #def unpad(self, s):
    #    return s[ :-ord( s[ len(s)-1 : ] ) ]
 
    ##def pad(self,s):
    #    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            
            if self.verbose:
                print('my public key: ', my_public_key)
                print('their public key: ', their_public_key)
                print('my private key: ', my_private_key)
            
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_hash))

        #using AES for ciphering, using the last 16 bytes from the shared_hash as key and the first 16 bytes as IV
        self.cipher = AES.new(self.shared_hash[len(self.shared_hash) -16 :].encode() , AES.MODE_CBC , self.shared_hash[:16].encode() )

    def send(self, data):
        if self.cipher:
            encrypted_data = self.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    #encprytion function, used to encrypt data via AES, 
    #it first pads the data to be a multiple of 16 bytes and is then used in AES
    #after the AES cipher, it encodes the value in base64
    def encrypt(self, data):
        self.cipher = AES.new(self.shared_hash[len(self.shared_hash) -16 :].encode() , AES.MODE_CBC , self.shared_hash[:16].encode() )
        data_padded = pad(data,self.cipher.block_size)
        return base64.b64encode(self.cipher.encrypt(data_padded) )

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = (self.conn.recv(pkt_len))
        if self.cipher:

            data = self.decrypt(encrypted_data)
            data = data.decode('utf-8')

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data


    def hmac_append(self, msg):
        # Append HMAC to the message before sending.
        hmac = HMAC.new(self.shared_hash.encode("ascii"), digestmod=SHA256)
        hmac.update(msg.encode("ascii"))
        return (msg + hmac.hexdigest())

    def hmac_isValid(self, msg):
        # Check if the received message is valid by
        # hashing the message and compare with the HMAC appended
        length = len(self.shared_hash)
        hmac = HMAC.new(self.shared_hash.encode("ascii"), digestmod=SHA256)
        msg_len = len(msg) - length
        message = (msg[: msg_len]).decode('utf-8')
        hmac.update(message.encode('ascii'))
        str_hmac = hmac.hexdigest()
        str_msg =  msg[len(message):len(msg)].decode('ascii')
        return str_hmac == str_msg

    def hmac_remove(self, msg):
        # Remove the HMAC appended to the end of the message
        length = len(self.shared_hash)
        return str(msg[:-(length)])

    # Decryption function used to decrypt incoming msg. 
    # The msg is first decoded from base64 into the AES cipher value
    # After it's decrypted and the value returned is sent to unpad() function to remove the padding.
    def decrypt(self, data):
        data = base64.b64decode(data)

        self.cipher = AES.new(self.shared_hash[len(self.shared_hash) -16 :].encode() , AES.MODE_CBC , self.shared_hash[:16].encode() )
        decrypted_data = self.cipher.decrypt(data)

        unpadded_data = unpad(decrypted_data,self.cipher.block_size)
        return unpadded_data

    def close(self):
        self.conn.close()
