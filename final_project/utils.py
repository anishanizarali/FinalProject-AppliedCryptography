from sage.all import PolynomialRing, ZZ
import socket
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256


HEADER_SIZE = 10


def server_socket(host, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
    return s


def send_data(c, data: bytes):

    np = (len(data) >> 12) + ((len(data) & (1<<12)-1) > 0)
    np_bytes = long_to_bytes(np)
    header = f'{hex(len(np_bytes))[2:]:>0{HEADER_SIZE}}'.encode()
    c.send(header + np_bytes)

    i = 0
    while i < np:
        j = i<<12
        if i < np-1:
            c.send(data[j: j+(1<<12)])        
        else:
            data = data[j:]
            len_bytes = long_to_bytes(len(data))
            header = f'{hex(len(len_bytes))[2:]:>0{HEADER_SIZE}}'.encode()
            c.send(header + len_bytes)
            data = data + b'\x00'*((1<<12) - len(data))
            c.send(data)
        i += 1


def recv_data(c):

    header = c.recv(HEADER_SIZE)
    data = c.recv(int(header.decode(), 16))
    np = bytes_to_long(data)

    data = b''
    i = 0
    while i < np:
        if i < np-1:
            data += c.recv(1<<12)
        else:
            len_bytes = c.recv(HEADER_SIZE)
            len_bytes = c.recv(int(len_bytes.decode(), 16))
            data += c.recv(1<<12)[:bytes_to_long(len_bytes)]
        i += 1

    return data


def polynomialHash(pol):
    
    R = PolynomialRing(ZZ, 'x')
    pol = R(list(pol))
    
    h = long_to_bytes(pol.subs(x=2))
    h = sha256(h).digest()
    
    return h
