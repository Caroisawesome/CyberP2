import sys
import socket
import os
import binascii
from Crypto.PublicKey import RSA
from aes import AESCipher

def extract_bin_data(filename):
    with open(filename, "rb") as binary_file:
        # Read the whole file at once
        data = bytearray( binary_file.read())
        return data

def get_RSA_pub(filename):
    with open(filename, 'r') as f:
        return RSA.importKey(f.read())

def build_cyphertext(i, X, RSA_pub):
    i = (i * RSA_pub.e ) % RSA_pub.n
    pows = 2**i
    #rsa_2k = RSA_pub.encrypt(pows, 32)[0]
    C_i = (pows * X ) % RSA_pub.n
    C_i = C_i.to_bytes(256, 'big', signed=False)
    return C_i

def update_guess(vals, b):
    vals = vals >>1
    if (b == 1):
        vals = vals + (1 << 255)
    return vals

def decode_message(vals_str,Y):
    vals = int(vals_str, 2)
    aes = get_new_aes(vals)
    m = aes.decrypt(Y)
    return m

def get_new_aes(aeskey):
    val_bytes = aeskey.to_bytes(32, 'big', signed=False)
    aes = AESCipher(val_bytes)
    return aes

def encrypt_with_new_aes(aeskey, test_msg):
    aes = get_new_aes(aeskey)
    return (aes.encrypt(test_msg), aes)

def get_val_int(val_str, i):
    if (val_str == ""):
        vals = 0
    else:
        vals = int(val_str,2)
    return vals << i

def get_socket():
    sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sc.connect(('127.0.0.1', 10005))
    sc.settimeout(2)
    return sc

def get_socket_response(sc,exp):
    rec = 0
    resp = b''
    while exp > rec:
        try:
            res = sc.recv(2048)
            #print("res", resp)
        except socket.timeout as e:
            print("socket timeout", e)
        except socket.error as e:
            print("socket error", e)
            print("res lenght = ", len(res))

        rec +=len(res)
        resp += res
    return resp

def send_msg_with_val(C_i, val_str, i,test_msg):
    vals = get_val_int(val_str,i)
    (Y_new, aes) = encrypt_with_new_aes(vals,test_msg)
    cpm = C_i + Y_new

    sc = get_socket()
    sc.sendall(cpm)

    exp = len(Y_new)
    resp = get_socket_response(sc,exp)

    msg = aes.decrypt(resp)

    try:
        msg = msg.decode().strip()
        expected_result = test_msg.upper()
        if (msg == expected_result):
            return True
        else:
            return False
    except UnicodeDecodeError:
        return False

if __name__== "__main__":
    bin_filename = sys.argv[1]
    pub_key_fn = sys.argv[2]
    XY = extract_bin_data(bin_filename)
    size_y = len(XY) - 256
    X = XY[0:256]
    Y = XY[256:257+size_y]
    test_msg = "Test"

    X = int.from_bytes(X, 'big', signed = False)
    RSA_pub = get_RSA_pub(pub_key_fn)

    val_str = ""

    for i in range(255,-1,-1):
        print(i)

        C_i = build_cyphertext(i, X, RSA_pub)

        val1 = "1"+val_str
        val2 = "0"+val_str

        if (send_msg_with_val(C_i, val1, i, test_msg)):
            val_str = val1
        elif (send_msg_with_val(C_i, val2, i, test_msg)):
            val_str = val2
        else:
            print("PROBLEM! neither worked!")

        print('saved bits', val_str)


    print('aes:', val_str)
    message = decode_message(val_str,bytes(Y))
    print("message", message)

    print("close socket")
    #sc.close()

