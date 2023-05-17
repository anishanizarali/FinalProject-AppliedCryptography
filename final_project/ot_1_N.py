from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from utils import polynomialHash
from ringgsw import RingGSW


class OTSender:

    
    def __init__(self, ring, msg_list, sigma=5):

        self.ring = ring
        self.msg_list = msg_list
        self.t = len(self.msg_list)
        
        self.rgsw = RingGSW(self.ring, sigma)
        self.sk, self.pk = self.rgsw.keygen()

        self.scheme = '1_OUT_OF_N'
    

    def random_encryption(self):
        
        self.a = self.ring.random_element()
        A = self.rgsw.encrypt(self.a, self.pk)
        
        return A


    def generate_ciphertexts(self, B):
        
        d = self.rgsw.decrypt(B, self.sk)
        ct_list = []
        
        for i in range(self.t):
            key = polynomialHash(d - (i * self.a))
            aes = AES.new(key, AES.MODE_CBC)
            ct = aes.encrypt(pad(self.msg_list[i], AES.block_size))
            ct_list.append(aes.iv + ct)
        
        return ct_list

    
class OTReceiver:
    
    
    def __init__(self, ring, pk, e, t):
        
        assert all([e >= 0, e < t])
        
        self.ring = ring
        self.rgsw = RingGSW(self.ring)
        self.pk = pk

        self.e = e
        self.t = t

        self.scheme = '1_OUT_OF_N'

        
    def homomorphic_encryption(self, A):
        
        self.b = self.ring.random_element()
        B = self.rgsw.encrypt(self.b, self.pk)
        
        e_A = self.rgsw.homMultConst(A, self.e)
        B = self.rgsw.homAdd(e_A, B)
        
        return B

    
    def decrypt(self, ct_list):
        
        key = polynomialHash(self.b)
        ct = ct_list[self.e]
        iv, ct = ct[:AES.block_size], ct[AES.block_size:]
        
        aes = AES.new(key, AES.MODE_CBC, iv)
        m_e = unpad(aes.decrypt(ct), AES.block_size)
        
        return m_e


def obliviousTransfer(ring, msg_list, e, sigma=5):

    sender = OTSender(ring, msg_list, sigma)
    client = OTReceiver(ring, sender.pk, e, sender.t)
    
    A = sender.random_encryption()
    B = client.homomorphic_encryption(A)
    ct_list = sender.generate_ciphertexts(B)
    m_e = client.decrypt(ct_list)

    return msg_list[e] == m_e
