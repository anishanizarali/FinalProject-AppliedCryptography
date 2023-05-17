from sage.all import var, RealDistribution, Integer, Matrix, vector
from math import floor, ceil, log2
from itertools import chain
from random import randrange


class RingGSW:

    
    def __init__(self, ring, sigma=5):
    
        assert ring.variable_name() == 'x'

        self.Rq = ring
        self.q = self.Rq.base().modulus()
        self.n = self.Rq.modulus().degree()
        
        var('x')
        assert self.Rq.modulus() == self.Rq(x**self.n + 1)
        assert all([self.q > 1, floor(log2(self.q)) == ceil(log2(self.q))])
        assert all([self.n > 1, floor(log2(self.q)) == ceil(log2(self.q))])

        self.k = ceil(log2(self.q))
        self.N = self.k << 1

        self.gauss = RealDistribution('gaussian', sigma)


    def powersOf2(self, pol):
        
        pol = self.Rq(pol)
        vec = []
        
        for i in range(self.k):
            tpol = self.Rq((1<<i) * pol)
            vec.append(tpol)
        
        return vector(self.Rq, vec)

    
    def bitDecomp(self, pol):
        
        pol = self.Rq(pol)
        vec = [self.Rq(0)] * self.k
        
        for i in range(self.n):
            coeff = Integer(pol[i])
            for j in range(self.k):
                vec[j] += self.Rq((coeff & 1) * x**i)
                coeff >>= 1
        
        return vector(self.Rq, vec)

    
    def bitDecompInv(self, vec):
        
        assert len(vec) == self.k
        pol = self.Rq(0)
        
        for i in range(self.k):
            pol += (1<<i) * vec[i]
        pol = self.Rq(pol)

        return pol

    
    def flatten(self, vec):
        
        assert len(vec) == self.k
        
        pol = self.bitDecompInv(vec)
        vec = self.bitDecomp(pol)
        
        return vec

    
    def matrixPowersOf2(self, mat):
        
        nr, nc = mat.nrows(), mat.ncols()
        newmat = Matrix(self.Rq, nr, [0] * nr * nc * self.k)
        
        for i in range(nr):
            v = vector(self.Rq, [])
            for j in range(nc):
                u = self.powersOf2(mat[i][j])
                v = vector(self.Rq, chain(v, u))
            newmat[i, :] = v
        
        return newmat

    
    def matrixBitDecomp(self, mat):
        
        nr, nc = mat.nrows(), mat.ncols()
        newmat = Matrix(self.Rq, nr, [0] * nr * nc * self.k)
        
        for i in range(nr):
            v = vector(self.Rq, [])
            for j in range(nc):
                u = self.bitDecomp(mat[i][j])
                v = vector(self.Rq, chain(v, u))
            newmat[i, :] = v
            
        return newmat

    
    def matrixBitDecompInv(self, mat):
        
        nr, nc = mat.nrows(), mat.ncols()
        assert nc % self.k == 0
        
        newmat = Matrix(self.Rq, nr, [0] * nr * (nc // self.k))
        
        for i in range(nr):
            v = vector(self.Rq, [])
            for j in range(0, nc, self.k):
                u = self.bitDecompInv(mat[i, j:j+self.k].row(0))
                u = vector(self.Rq, [u])
                v = vector(self.Rq, chain(v, u))
            newmat[i, :] = v
            
        return newmat

    
    def matrixFlatten(self, mat):
        
        assert mat.ncols() % self.k == 0
        
        newmat = self.matrixBitDecompInv(mat)
        newmat = self.matrixBitDecomp(newmat)
        
        return newmat

    
    def keygen(self):
        
        t = self.Rq.random_element()
        b1 = self.Rq.random_element()
        
        err = self.Rq([floor(self.gauss.get_random_element()) for _ in range(self.n)])
        b2 = b1 * t + err
        
        sk = vector(self.Rq, chain(self.powersOf2(1), self.powersOf2(-t)))
        sk = Matrix(self.Rq, self.N, sk)
        pk = Matrix(self.Rq, 1, [b2, b1])
        
        return sk, pk


    def encrypt(self, pt, pk):
        
        r = []
        
        for i in range(self.N):
            pol = 0
            for j in range(self.n):
                pol += randrange(2) * x**j
            r.append(pol)
        
        r = Matrix(self.Rq, self.N, r)
        ct = self.Rq(pt) * Matrix.identity(self.N)
        ct += self.matrixBitDecomp(r * pk)
        ct = self.matrixFlatten(ct)
        
        return ct

    
    def decrypt(self, ct, sk):
        
        v = (ct[0:self.k, :] * sk).column(0)
        pt = 0

        for i in range(self.n):
            zi = 0
            for j in range(self.k-1, -1, -1):
                b = v[j][i] - (zi<<j)
                b = all([b >= self.q>>2, b < 3*(self.q>>2)])
                zi += b << (self.k-1-j)
            pt += zi * x**i
        pt = self.Rq(pt)
        
        return pt

    
    def homMultConst(self, ct, g):
        
        gct = self.matrixFlatten(self.Rq(g) * Matrix.identity(self.N))
        gct = self.matrixFlatten(gct * ct)
        
        return gct

    
    def homAdd(self, ct1, ct2):
        
        return self.matrixFlatten(ct1 + ct2)
