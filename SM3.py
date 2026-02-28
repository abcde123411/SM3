class SM3(object):

    def __init__(self, hex_string):
        self.hex_string = hex_string
        self.bin_string = bin(int(hex_string, 16))[2:].zfill(4*len(hex_string))
        self.IV = '7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e'
        self.T = ['79cc4519'] * 16 + ['7a879d8a'] * 48
        self.B = []
        self.W = [''] * 68
        self.W_ = [''] * 64

    @staticmethod
    # 循环左移
    def shift_to_left(string, num):
        return string[num % len(string):] + string[:num % len(string)]

    @staticmethod
    # 异或
    def x_o_r(string_to_number_list):
        result = 0
        for i in range(len(string_to_number_list)):
            result = result ^ string_to_number_list[i]
        return bin(result)[2:]

    @staticmethod
    # 取反
    def n_o_t(string):
        op1 = '1' * len(string)
        op2 = string
        result = bin(int(op1, 2) - int(op2, 2))[2:].zfill(len(string))
        return result

    @staticmethod
    def ff(j, x, y, z):
        if 0 <= j <= 15:
            result = SM3.x_o_r([int(x, 2), int(y, 2), int(z, 2)]).zfill(32)
        else:
            result = bin((int(x, 2) & int(y, 2)) | (int(x, 2) & int(z, 2)) | (int(y, 2) & int(z, 2)))[2:].zfill(32)
        return result

    @staticmethod
    def gg(j, x, y, z):
        if 0 <= j <= 15:
            result = SM3.x_o_r([int(x, 2), int(y, 2), int(z, 2)]).zfill(32)
        else:
            result = bin((int(x, 2) & int(y, 2)) | (int(SM3.n_o_t(x), 2) & int(z, 2)))[2:].zfill(32)
        return result

    @staticmethod
    def p0(x):
        result = SM3.x_o_r([int(x, 2), int(SM3.shift_to_left(x, 9), 2), int(SM3.shift_to_left(x, 17), 2)]).zfill(32)
        return result

    @staticmethod
    def p1(x):
        result = SM3.x_o_r([int(x, 2), int(SM3.shift_to_left(x, 15), 2), int(SM3.shift_to_left(x, 23), 2)]).zfill(32)
        return result

    def cf(self, j, v, b):
        abcdefgh = [''] * 8
        for i in range(8):
            abcdefgh[i] = v[i*32:i*32+32]
        ss1 = SM3.shift_to_left(bin(int(SM3.shift_to_left(abcdefgh[0], 12), 2) + int(abcdefgh[4], 2) +
                                    int(SM3.shift_to_left(self.T[j], j % 32), 2))[2:].zfill(32)[-32:], 7)
        ss2 = SM3.x_o_r([int(ss1, 2), int(SM3.shift_to_left(abcdefgh[0], 12), 2)]).zfill(32)
        tt1 = bin(int(SM3.ff(j, abcdefgh[0], abcdefgh[1], abcdefgh[2]), 2) + int(abcdefgh[3], 2) + int(ss2, 2) +
                  int(self.W_[j], 2))[2:].zfill(32)[-32:]
        tt2 = bin(int(SM3.gg(j, abcdefgh[4], abcdefgh[5], abcdefgh[6]), 2) + int(abcdefgh[7], 2) + int(ss1, 2) +
                  int(self.W[j], 2))[2:].zfill(32)[-32:]
        abcdefgh[3] = abcdefgh[2]
        abcdefgh[2] = SM3.shift_to_left(abcdefgh[1], 9)
        abcdefgh[1] = abcdefgh[0]
        abcdefgh[0] = tt1
        abcdefgh[7] = abcdefgh[6]
        abcdefgh[6] = SM3.shift_to_left(abcdefgh[5], 19)
        abcdefgh[5] = abcdefgh[4]
        abcdefgh[4] = SM3.p0(tt2)
        result = abcdefgh[0] + abcdefgh[1] + abcdefgh[2] + abcdefgh[3] + \
            abcdefgh[4] + abcdefgh[5] + abcdefgh[6] + abcdefgh[7]
        return result

    def hash(self):
        sm3 = None
        # 1. 填充
        l = len(self.bin_string)
        k = 0
        while (l+1+k) % 512 != 448:
            k += 1
        self.bin_string += '1' + '0' * k + bin(l)[2:].zfill(64)

        # 2. 迭代
        n = (l+1+k+64) // 512
        for i in range(n):
            self.B.append(self.bin_string[i*512:i*512+512])
        # T
        for j in range(64):
            self.T[j] = bin(int(self.T[j], 16))[2:].zfill(32)
        # 计算 W 和 W‘
        for i in range(n):
            # W
            for j in range(68):
                if 0 <= j <= 15:
                    self.W[j] = self.B[i][j*32:j*32+32]
                else:
                    op1 = SM3.p1(SM3.x_o_r([int(self.W[j-16], 2), int(self.W[j-9], 2),
                                            int(SM3.shift_to_left(self.W[j-3], 15), 2)]).zfill(32))
                    op2 = SM3.shift_to_left(self.W[j-13], 7)
                    op3 = self.W[j-6]
                    op4 = SM3.x_o_r([int(op1, 2), int(op2, 2), int(op3, 2)]).zfill(32)
                    self.W[j] = op4
            # W’
            for j in range(64):
                op1 = SM3.x_o_r([int(self.W[j], 2), int(self.W[j+4], 2)]).zfill(32)
                self.W_[j] = op1
            # 64轮迭代
            v = bin(int(self.IV, 16))[2:].zfill(256)
            for j in range(64):
                v = SM3.cf(self, j, v, self.B)
            hex_string = hex(int(v, 2))[2:].zfill(64)
            sm3 = hex(int(hex_string, 16) ^ int(self.IV, 16))[2:].zfill(64)
            self.IV = sm3
        return sm3


test1 = SM3('616263').hash()
print(test1)
test2 = SM3('61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364').hash()
print(test2)
