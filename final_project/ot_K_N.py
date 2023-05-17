from sage.all import Zmod
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from utils import polynomialHash
from ringgsw import RingGSW


class OTSender:


    def __init__(self, ring, msg_list, sigma=5):

        self.ring = ring
        self.Zq = Zmod(self.ring.base().modulus())
        self.msg_list = msg_list
        self.t = len(self.msg_list)

        self.rgsw = RingGSW(self.ring, sigma)
        self.sk, self.pk = self.rgsw.keygen()
        self.fake_sk, _ = self.rgsw.keygen()

        self.scheme = 'K_OUT_OF_N'
    
    def random_encryption(self):

        self.a = self.ring.random_element()
        self.alpha_1 = self.Zq.random_element()
        while self.alpha_1 < 1: self.alpha_1 = self.Zq.random_element()

        A = self.rgsw.encrypt(self.a, self.pk)
        T_A = self.rgsw.homMultConst(A, self.alpha_1)

        return A, T_A
    

    def generate_ciphertexts(self, U, T_B):

        self.alpha_2 = self.Zq.random_element()
        while self.alpha_2 < 1: self.alpha_2 = self.Zq.random_element()

        ct_list = []

        for i in range(self.t):
            X = self.rgsw.homMultConst(T_B, self.alpha_2 * (self.alpha_1 + i))
            d = self.rgsw.decrypt(X, self.fake_sk)
            key = polynomialHash(d)

            aes = AES.new(key, AES.MODE_CBC)
            ct = aes.encrypt(pad(self.msg_list[i], AES.block_size))
            ct_list.append(aes.iv + ct)
        
        V = [self.rgsw.homMultConst(U_i, self.alpha_2) for U_i in U]

        return ct_list, V


class OTReceiver:


    def __init__(self, ring, pk, e, t):

        assert all([w >= 0 and w < t for w in e])

        self.ring = ring
        self.Zq = Zmod(self.ring.base().modulus())
        self.rgsw = RingGSW(self.ring)
        self.pk = pk
        self.fake_sk = None

        self.e = e
        self.t = t

        self.scheme = 'K_OUT_OF_N'
    

    def homomorphic_encryption(self, A, T_A):

        self.beta = self.Zq.random_element()
        while self.beta < 1: self.beta = self.Zq.random_element()

        self.gamma = self.Zq.random_element()
        while self.gamma < 1: self.gamma = self.Zq.random_element()
        if self.gamma % 2 == 0: self.gamma += 1

        T_B = self.rgsw.homMultConst(A, self.beta)
        U = []

        for i in range(len(self.e)):
            U_i = self.rgsw.homMultConst(A, self.e[i])
            U_i = self.rgsw.homAdd(T_A, U_i)
            U_i = self.rgsw.homMultConst(U_i, self.beta * self.gamma)
            U.append(U_i)
        
        return U, T_B


    def verify_fake_sk(self, fake_sk):

        self.fake_sk = fake_sk
        
        err = self.rgsw.matrixBitDecomp(self.pk) * self.fake_sk
        err = err.row(0)[0]

        for cf in err:
            if cf >= self.rgsw.q>>2 and cf < 3*(self.rgsw.q>>2):
                return True
        
        return False


    def decrypt(self, ct_list, V):

        messages = []

        for i in range(len(self.e)):
            X = self.rgsw.homMultConst(V[i], 1/self.gamma)
            d = self.rgsw.decrypt(X, self.fake_sk)
            key = polynomialHash(d)
            ct = ct_list[self.e[i]]
            iv, ct = ct[:AES.block_size], ct[AES.block_size:]

            aes = AES.new(key, AES.MODE_CBC, iv)
            msg = unpad(aes.decrypt(ct), AES.block_size)
            messages.append(msg)
        
        return messages


def obliviousTransfer(ring, msg_list, e, sigma=5):

    sender = OTSender(ring, msg_list, sigma)
    client = OTReceiver(ring, sender.pk, e, sender.t)

    A, T_A = sender.random_encryption()
    U, T_B = client.homomorphic_encryption(A, T_A)
    
    assert client.verify_fake_sk(sender.fake_sk), "invalid dummy secret key"

    ct_list, V = sender.generate_ciphertexts(U, T_B)
    messages = client.decrypt(ct_list, V)

    assert all([msg_list[e[i]] == messages[i] for i in range(len(e))])
