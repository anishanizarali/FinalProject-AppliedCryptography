from utils import send_data, recv_data
import ot_1_N, ot_K_N
import socket
import pickle


def on_connect(s):

    ring = pickle.loads(recv_data(s))
    sender_pk = pickle.loads(recv_data(s))
    t = pickle.loads(recv_data(s))

    choice = []
    while len(choice) == 0:
    
        choice = input(f'\nenter your choice(s) (0 to {t-1}): ').split(',')
        choice = [int(c) for c in choice]
    
        if len(choice) == 0 or any([c < 0 or c >= t for c in choice]):
            print('invalid choice')
            choice = []

    if len(choice) == 1:
        ot_recv = ot_1_N.OTReceiver(ring, sender_pk, choice[0], t)
    else:
        ot_recv = ot_K_N.OTReceiver(ring, sender_pk, choice, t)

    send_data(s, pickle.dumps(ot_recv.scheme))

    return ot_recv, choice


def ot_1_out_of_N(s, ot_recv):

    A = pickle.loads(recv_data(s))
    print('\nrecevied the random encryption (A)\n')

    print('sending homomorphic encryption of A (B)\n')
    B = ot_recv.homomorphic_encryption(A)
    send_data(s, pickle.dumps(B))

    ct_list = pickle.loads(recv_data(s))
    print('recevied symmetric AES ciphertexts:\n')
    for i in range(len(ct_list)):
        print(f'{i}. {ct_list[i].hex()}')

    return ot_recv.decrypt(ct_list)


def ot_K_out_of_N(s, ot_recv):

    A, T_A = pickle.loads(recv_data(s))
    print('\nreceived the random encryption (A, T_A)\n')

    print('sending homomorphic encryptions of A (U, T_B)\n')
    U, T_B = ot_recv.homomorphic_encryption(A, T_A)
    send_data(s, pickle.dumps((U, T_B)))

    sender_fake_sk = pickle.loads(recv_data(s))
    print('received dummy secret key\nverification: ', end='')

    if ot_recv.verify_fake_sk(sender_fake_sk):
        print('[OK]\n')
    else:
        print('[Failed]\n')
        raise AssertionError('invalid dummy secret key')

    ct_list, V = pickle.loads(recv_data(s))
    print('received symmetric AES ciphertexts:')
    for i in range(len(ct_list)):
        print(f'{i}. {ct_list[i].hex()}')

    return ot_recv.decrypt(ct_list, V)


def main(host, port):

    s = socket.socket()
    s.connect((host, port))
    print('\nconnected to sender\n')

    try:

        print('received parameters (ring, public key)')
        ot_recv, choice = on_connect(s)

        if ot_recv.scheme == '1_OUT_OF_N':
            msg = ot_1_out_of_N(s, ot_recv)
            print(f'\ndecrypted message:\n{choice[0]}. {msg.hex()}\n')
        
        elif ot_recv.scheme == 'K_OUT_OF_N':
            msg = ot_K_out_of_N(s, ot_recv)
            print(f'\ndecrypted message(s):\n')
            for i in range(len(msg)):
                print(f'{choice[i]}. {msg[i].hex()}')

    except Exception as e:
        print(str(e))

    s.close()
    print('\n[*] connection closed\n')


if __name__ == '__main__':

    main('localhost', 3000)
