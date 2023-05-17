from sage.all import var, PolynomialRing, Zmod
from math import floor, ceil, log2
from random import randrange, sample
from ringgsw import RingGSW
import ot_1_N, ot_K_N


class RingGSWOTTests:

    
    def __init__(self, q, n, sigma=5):

        assert all([q > 1, floor(log2(q)) == ceil(log2(q))])
        assert all([n > 1, floor(log2(n)) == ceil(log2(n))])
        
        self.k = ceil(log2(q))
        self.sigma = sigma
        
        var('x')
        self.Zq = Zmod(q)
        F = PolynomialRing(self.Zq, 'x')
        self.Rq = F.quotient(x**n + 1, 'x')
        
        self.rgsw = RingGSW(self.Rq, self.sigma)
        self.sk, self.pk = self.rgsw.keygen()

        
    def dotProduct(self, v1, v2):
        
        assert len(v1) == len(v2)
        
        prod = self.Rq(0)
        for u, v in zip(v1, v2):
            prod += u * v
        
        return prod

    
    def propertiesTest(self):

        a = self.Rq.random_element()
        b = self.Rq.random_element()
        v = [self.Rq.random_element() for _ in range(self.k)]

        try:
            assert self.rgsw.bitDecompInv(self.rgsw.bitDecomp(a)) == a

            w = self.rgsw.flatten(v)
            t = self.rgsw.bitDecomp(a)
            y = self.rgsw.powersOf2(b)
            z = self.rgsw.bitDecompInv(v)

            assert all([
                self.dotProduct(t, y) == a * b,
                self.dotProduct(v, y) == self.dotProduct(w, y) == z * b
            ])

            print("powersOf2, bitDecomp, bitDecompInv, flatten [OK]\n")

        except Exception as e:
            print("powersOf2, bitDecomp, bitDecompInv, flatten [Failed]")
            print(f"\n{str(e)}\n")


    def encryptDecryptTest(self):

        m = self.Rq.random_element()
        ct = self.rgsw.encrypt(m, self.pk)
        z = self.rgsw.decrypt(ct, self.sk)

        try:
            assert z == m
            print("encryption, decryption [OK]\n")

        except AssertionError:
            print("encryption, decryption [Failed]")
            print(f"\nactual: {m}\n\nobtained: {z}\n")


    def homMultConstTest(self, L=20):
        
        msg = self.Rq.random_element()
        gct = self.rgsw.encrypt(msg, self.pk)
        
        i = 0
        
        try:
            while i < L:

                g = self.Zq.random_element()
                if g == 0: continue
                
                gct = self.rgsw.homMultConst(msg, g)
                msg *= self.Rq(g)

                z = self.rgsw.decrypt(gct, self.sk)
                assert z == msg
                
                i += 1
            
            print("homomorphic constant multiplication [OK]\n")
        
        except AssertionError:
            print(f"homomorphic constant multiplication [Failed at op. {i+1}/{L}]")
            print(f"\nactual: {msg}\n\nobtained: {z}\n")


    def homAddTest(self, L=20):
        
        msg = self.Rq.random_element()
        hct = self.rgsw.encrypt(msg, self.pk)
        
        i = 0
        
        try:
            while i < L:

                m = self.Rq.random_element()
                ct = self.rgsw.encrypt(m, self.pk)

                hct = self.rgsw.homAdd(hct, ct)
                msg += m

                z = self.rgsw.decrypt(hct, self.sk)
                assert z == msg
                
                i += 1
            
            print("homomorphic addition [OK]\n")
        
        except AssertionError:
            print(f"homomorphic addition [Failed at op. {i+1}/{L}]")
            print(f"\nactual: {msg}\n\nobtained: {z}\n")
            

    def ot_1_out_of_N_Test(self, N=20):
        
        e = randrange(N)
        messages = [bytes([randrange(256) for _ in range(10)]) for _ in range(N)]

        try:
            assert ot_1_N.obliviousTransfer(self.Rq, messages, e, self.sigma)
            print("1 out of N oblivious transfer [OK]\n")

        except Exception as e:
            print(f"1 out of N oblivious transfer [Failed]")
            print(f"\n{str(e)}\n")


    def ot_K_out_of_N_Test(self, N=20):

        e = sample(range(N), randrange(2, N))
        messages = [bytes([randrange(256) for _ in range(10)]) for _ in range(N)]

        try:
            assert ot_K_N.obliviousTransfer(self.Rq, messages, e, self.sigma)
            print("K out of N oblivious transfer [OK]\n")

        except Exception as e:
            print(f"K out of N oblivious transfer [Failed]")
            print(f"\n{str(e)}\n")


    def runAllTests(self):

        self.propertiesTest()
        self.encryptDecryptTest()
        self.homMultConstTest()
        self.homAddTest()
        self.ot_1_out_of_N_Test()
        self.ot_K_out_of_N_Test()


def main():

    test = RingGSWOTTests(q=2**17, n=2**4, sigma=5)
    test.runAllTests()


if __name__ == '__main__':

    main()
