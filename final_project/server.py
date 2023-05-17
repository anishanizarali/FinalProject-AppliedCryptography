from sage.all import var, PolynomialRing, Zmod
from utils import server_socket, send_data, recv_data
import ot_1_N, ot_K_N
from os import urandom
import pickle


def on_new_connect(client, msg_list):

    q, n, sigma = 2**17, 2**4, 5
    var('x')
    
    ring = PolynomialRing(Zmod(q), 'x').quotient(x**n + 1, 'x')
    send_data(client, pickle.dumps(ring))

    ot_sender = ot_1_N.OTSender(ring, msg_list, sigma)
    send_data(client, pickle.dumps(ot_sender.pk))
    send_data(client, pickle.dumps(len(msg_list)))
    
    scheme = pickle.loads(recv_data(client))
    if scheme == 'K_OUT_OF_N':

        sk, pk = ot_sender.sk, ot_sender.pk
        ot_sender = ot_K_N.OTSender(ring, msg_list, sigma)
        ot_sender.sk = sk
        ot_sender.pk = pk

    return ot_sender


def ot_1_out_of_N(client, ot_sender):

    print('\nsending a random encryption (A)\n')
    A = ot_sender.random_encryption()
    send_data(client, pickle.dumps(A))

    B = pickle.loads(recv_data(client))
    print('recieved homomorphic encryption of A (B)\n')

    print('sending symmetric AES ciphertexts\n')
    ct_list = ot_sender.generate_ciphertexts(B)
    send_data(client, pickle.dumps(ct_list))


def ot_K_out_of_N(client, ot_sender):

    print('sending a random encryption (A, T_A)\n')
    A, T_A = ot_sender.random_encryption()
    send_data(client, pickle.dumps((A, T_A)))

    U, T_B = pickle.loads(recv_data(client))
    print('received homomorphic encryptions of A (U, T_B)\n')

    print('sending dummy secret key\n')
    send_data(client, pickle.dumps(ot_sender.fake_sk))

    print('sending symmetric AES ciphertexts\n')
    ct_list, V = ot_sender.generate_ciphertexts(U, T_B)
    send_data(client, pickle.dumps((ct_list, V)))


def main(host, port):

    server_sock = server_socket(host, port)
    print(f'\n[*] listening on port {port}\n')

    client, _ = server_sock.accept()
    print('connection accepted\n')
    msg_list = [urandom(16) for _ in range(6)]

    print('messages (visible to sender):\n')
    for i in range(len(msg_list)):
        print(f'{i}. {msg_list[i].hex()}')

    print('\nsharing parameters\n')
    ot_sender = on_new_connect(client, msg_list)

    if ot_sender.scheme == '1_OUT_OF_N':
        ot_1_out_of_N(client, ot_sender)
    elif ot_sender.scheme == 'K_OUT_OF_N':
        ot_K_out_of_N(client, ot_sender)

    server_sock.close()
    print('[*] connection closed\n')


if __name__ == '__main__':

    main('localhost', 3000)
