import struct
import base64

from Crypto.Cipher import AES

from dh import create_dh_key, calculate_dh_secret

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = ""
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the clientasdsad
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

        # Default XOR algorithm can only take a key of length 32
        self.cipher = AES.new(self.shared_hash[len(self.shared_hash) -16 :] , AES.MODE_CBC , self.shared_hash[:16] )

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

    def encrypt(self, data):
        #data = pad(str(data))
        data_padded = pad(str(data))
        return base64.b64encode(self.cipher.encrypt(data_padded) )

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = (self.conn.recv(pkt_len))
        print(pkt_len)
        if self.cipher:
            #second_cipher = AES.new(self.shared_hash[len(self.shared_hash) -16:] , AES.MODE_CBC , self.shared_hash[:16] )
            print("shared_hash: "+ self.shared_hash)
            data = self.decrypt(encrypted_data)
            print(data)
            data = data.decode('utf-8')
            #data = unpad(data.decode('ascii'))

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        print("Ending recv(), data: " + str(data))
        return data

    def decrypt(self, encrypted_data):
        data = encrypted_data
        print("--------------")
        print(data)
        print("in decrypt, data: " + str(data))
        data = base64.b64decode(data)
        print("in decrypt, Base64 data: " + str(data))
        second_cipher = AES.new(self.shared_hash[len(self.shared_hash) -16:] , AES.MODE_CBC , self.shared_hash[:16] )
        unpadded_data = unpad(second_cipher.decrypt( data))
        print("in decrypt, Unpadded data: " + str(unpadded_data))
        return unpadded_data
    
    def close(self):
        self.conn.close()
