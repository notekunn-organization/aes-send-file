from BitVector import BitVector
from utils import s_box_table, text_to_number, iv_s_box_table
import math

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


class AESManager:
    def __init__(self, style=128, debug=False):
        self.is_debug = debug
        if style == 128:
            self.rounds = 10
            self.cipher_word = 4
        elif style == 192:
            self.rounds = 12
            self.cipher_word = 6
        elif style == 256:
            self.rounds = 14
            self.cipher_word = 8
        else:
            raise Exception("Chi ma hoa AES-128, AES-192 va AES-256")
        self.round_keys = []
        return

    def debug(self, *args):
        if self.is_debug:
            print(*args)

    # def gen_round_keys(self, passphrase_bv):
    #     self.round_keys = []
    #     self.round_keys.append(self.find_round_key(passphrase_bv.get_bitvector_in_hex(), 0))
    #     for i in range(self.rounds - 1):
    #         self.round_keys.append(self.find_round_key(self.round_keys[i], i + 1))
    #     print(self.round_keys)
    #     return

    def encrypt(self, cipher_key: str, plaintext: str):
        result_cipher_text = ""
        cipher_key = self.handler_cipher_key(cipher_key)
        self.debug("Passphrase: %s" % cipher_key)
        cipher_key = BitVector(textstring=cipher_key)
        # gen round keys
        round_keys = self.expand_key(cipher_key.get_bitvector_in_hex())
        self.debug("Round key: ", round_keys)
        # format plain text
        message = self.format_text(plaintext)
        self.debug("Plain text: %s" % message)
        start = 0  # diem bat dau cua segment
        end = 0  # diem ket thuc
        length = len(message)  # Do dai cua chuoi
        count_seg = math.ceil(length / 16)  # so cum 16 ky tu
        # duyet het cum 16 ky tu
        for x in range(count_seg):
            self.debug("Segment #%d" % (x + 1))
            if end + 16 < length:
                plaintext_seg = message[start:end + 16]
            else:
                plaintext_seg = message[start: length]
                plaintext_seg.ljust(16, '\0')
            # add cipher key
            result = self.add_round_key(BitVector(textstring=plaintext_seg).get_bitvector_in_hex(),
                                        round_keys[0])
            for y in range(self.rounds - 1):
                self.debug("Round #%d" % (y + 1))
                # hex_str = result_bv.get_bitvector_in_hex()

                # sub bytes
                result = self.sub_bytes(result)

                # shift row
                result = self.shift_rows(result)

                # mix column
                result = self.mix_columns(result)

                # add round key
                result = self.add_round_key(result, round_keys[y + 1])

            self.debug("Round #%d" % self.rounds)
            # Round last
            # hex_str = result_bv.get_bitvector_in_hex()

            # sub bytes
            result = self.sub_bytes(result)

            # shift row
            result = self.shift_rows(result)

            # add round key
            result = self.add_round_key(result, round_keys[self.rounds])

            # write hex
            result_cipher_text = result_cipher_text + result  # get_hex_string_from_bitvector

            # next segment
            start = start + 16
            end = end + 16

        return result_cipher_text

    def decrypt(self, cipher_key: str, ciphertext: str):
        result_plain_text = ""
        cipher_key = self.handler_cipher_key(cipher_key)
        print("Passphrase: %s" % cipher_key)
        cipher_key = BitVector(textstring=cipher_key)
        # gen round keys
        round_keys = self.expand_key(cipher_key.get_bitvector_in_hex())
        print("Cipher text: %s" % ciphertext)

        start = 0
        end = 32
        length = len(ciphertext)
        count_seg = math.ceil(length / 32)  # so cum 32 bit ( 2 bit 1 ky tu )
        for x in range(count_seg):
            self.debug("Segment #%d" % (x + 1))
            ciphertext_seg = ciphertext[start:end]

            # add round key
            result = self.add_round_key(hex_str=ciphertext_seg, round_key=round_keys[self.rounds])

            # inverse shift row
            result = self.inv_shift_rows(result)

            # inverse sub byte
            result = self.inv_sub_bytes(result)

            for y in range(self.rounds - 1, 0, -1):
                # add round key
                result = self.add_round_key(hex_str=result, round_key=round_keys[y])

                # mix column
                result = self.inv_mix_columns(result)

                # inverse shift row
                result = self.inv_shift_rows(result)

                # inverse sub byte
                result = self.inv_sub_bytes(result)

            # add cipher key
            result = self.add_round_key(hex_str=result, round_key=round_keys[0])

            output_bv = BitVector(hexstring=self.inv_format_text(result))
            plaintext = output_bv.get_bitvector_in_ascii()
            plaintext = plaintext.replace('\x00', '')
            result_plain_text = result_plain_text + plaintext
            start = start + 32
            end = end + 32

        return result_plain_text

    @staticmethod
    def sub_bytes(hex_str):
        result = ""
        for loop in range(0, math.ceil(len(hex_str) / 2)):
            x = text_to_number(hex_str[loop * 2])
            y = text_to_number(hex_str[loop * 2 + 1])
            s_box_char = s_box_table[x][y]
            result = result + s_box_char
        return result

    @staticmethod
    def inv_sub_bytes(hex_str):
        result = ""
        for loop in range(0, math.ceil(len(hex_str) / 2)):
            x = text_to_number(hex_str[loop * 2])
            y = text_to_number(hex_str[loop * 2 + 1])
            s_box_char = iv_s_box_table[x][y]
            result = result + s_box_char
        return result

    @staticmethod
    def shift_rows(hex_str):
        """
        0 4 8  12     0  4  8  12 # Giữ nguyên
        1 5 9  13     5  9  13 1  # Dịch trái 1
        2 6 10 14  => 10 14 2  6  # Dịch trái 2
        3 7 11 15     15 3  7  11 # Dịch trái 3
        """
        # Cot 1 -> 0 5 10 15
        result = hex_str[0:2] + hex_str[10: 12] + hex_str[20:22] + hex_str[30:32]
        # Cột 2 -> 4 9 14 3
        result = result + hex_str[8:10] + hex_str[18:20] + hex_str[28:30] + hex_str[6:8]
        # Cột 3 -> 8 13 2 7
        result = result + hex_str[16:18] + hex_str[26:28] + hex_str[4:6] + hex_str[14:16]
        # Cột 4 -> 12 1 5 11
        result = result + hex_str[24:26] + hex_str[2:4] + hex_str[12:14] + hex_str[22:24]
        return result

    @staticmethod
    def rot_word(hex_str):
        result = hex_str[2:8] + hex_str[0:2]
        return result

    @staticmethod
    def inv_shift_rows(hex_str):
        """
        0 4 8  12     0  4  8  12  # Giữ nguyên
        1 5 9  13     13 1  5  9   # Dịch phải 1
        2 6 10 14  => 10 14 2  6   # Dịch phải 2
        3 7 11 15     7  11 15 3   # Dịch phải 3
        """
        # Cột 1 -> 0 13 10 7
        result = hex_str[0:2] + hex_str[26:28] + hex_str[20:22] + hex_str[14:16]
        # Cột 2 -> 4 1 14 11
        result = result + hex_str[8:10] + hex_str[2:4] + hex_str[28:30] + hex_str[22:24]
        # Cột 3 -> 8 5 2 15
        result = result + hex_str[16:18] + hex_str[10:12] + hex_str[4:6] + hex_str[30:32]
        # Cột 4 -> 12 9 6 3
        result = result + hex_str[24:26] + hex_str[18:20] + hex_str[12:14] + hex_str[6:8]
        return result

    @staticmethod
    def mix_single_column(word):  # hàm mix column cho 1 word - gồm 1 mảng 4 số
        # Sec 4.1.2 iThe Design of Rijndael
        t = word[0] ^ word[1] ^ word[2] ^ word[3]
        u = word[0]
        word[0] ^= t ^ xtime(word[0] ^ word[1])
        word[1] ^= t ^ xtime(word[1] ^ word[2])
        word[2] ^= t ^ xtime(word[2] ^ word[3])
        word[3] ^= t ^ xtime(word[3] ^ u)
        result = ""
        for i in range(4):
            result += hex(word[i])[2:].rjust(2, '0')
        return result

    @staticmethod
    def mix_columns(hex_str):
        dec_vector = BitVector(hexstring=hex_str).get_decimal_vector()
        result = ""
        for i in range(0, len(dec_vector), 4):
            # mix column từng hàng
            # result = AESManager.mix_single_column(hex_str[i * 8: (i+1) *8])
            result += AESManager.mix_single_column(dec_vector[i: i + 4])
        return result

    @staticmethod
    def inv_mix_columns(hex_str):
        s = BitVector(hexstring=hex_str).get_decimal_vector()
        for i in range(4):
            # Sec 4.1.3 in The Design of Rijndael
            # Nghịch đảo ma trận
            u = xtime(xtime(s[i * 4] ^ s[i * 4 + 2]))
            v = xtime(xtime(s[i * 4 + 1] ^ s[i * 4 + 3]))
            s[i * 4 + 0] ^= u
            s[i * 4 + 1] ^= v
            s[i * 4 + 2] ^= u
            s[i * 4 + 3] ^= v
        result = ""
        for i in range(len(s)):
            result += hex(s[i])[2:].rjust(2, '0')
        # Làm tương tự mix column nhưng đã nghịch đảo ma trận
        return AESManager.mix_columns(result)

    @staticmethod
    def add_round_key(hex_str, round_key):
        bv = BitVector(hexstring=hex_str)
        round_key_bv = BitVector(hexstring=round_key)
        result_bv = bv ^ round_key_bv
        return result_bv.get_bitvector_in_hex()

    def handler_cipher_key(self, cipher_key: str):
        cipher_key_len = self.cipher_word * 4  # 1 word = 4 chu
        if len(cipher_key) > cipher_key_len:
            self.debug("Dai qua %d ky tu, cat bot." % cipher_key_len)
            return cipher_key[0:cipher_key_len]
        if len(cipher_key) < cipher_key_len:
            self.debug("It hon %d ky tu, them khoang trang." % cipher_key_len)
            return cipher_key.ljust(cipher_key_len, ' ')
            # Them khoang trang vao ben phai
        return cipher_key

    def valid_cipher_key(self, cipher_key: str):
        cipher_key_len = self.cipher_word * 4
        if len(cipher_key) > cipher_key_len:
            return "Cipher key dài quá %d ký tự" % cipher_key_len
        if len(cipher_key) < cipher_key_len:
            return "Cipher key ít hơn %d ký tự." % cipher_key_len
            # Them khoang trang vao ben phai
        return None

    @staticmethod
    def xor(hex1, hex2):
        bv1 = BitVector(hexstring=hex1)
        bv2 = BitVector(hexstring=hex2)
        bv3 = bv1 ^ bv2
        return bv3.get_bitvector_in_hex()

    def expand_key(self, cipher_key):
        r_con = ['01000000', '02000000', '04000000', '08000000', '10000000',
                 '20000000', '40000000', '80000000', '1b000000', '36000000',
                 '6c000000', 'd8000000', 'ab000000', '4d000000']
        max_word = (self.rounds + 1) * 4
        i = 0
        for n_w in range(self.cipher_word, max_word, 1):
            # Copy previous word
            n_bit = n_w * 8  # 1 word 8 bit hex
            word = cipher_key[n_bit - 8: n_bit]
            # Schedule_core mỗi 1 row
            if n_w % self.cipher_word == 0:
                # Rotate word
                word = self.rot_word(word)

                # sub bytes
                word = self.sub_bytes(word)

                # xor Rcon
                word = self.xor(word, r_con[i])
                # increase i
                i = i + 1
            elif self.cipher_word == 8 and n_w % self.cipher_word == 4:
                # Sub bytes mỗi 4 word khi sử dụng
                # 256-bit key.
                word = self.sub_bytes(word)

            # Word tương đương
            previous = cipher_key[(n_w - self.cipher_word) * 8: (n_w - self.cipher_word + 1) * 8]
            # Xor với word tương đương
            word = self.xor(word, previous)
            # Nối vào
            cipher_key = cipher_key + word
        # Trả về các tập hợp 32bit = 4 word = 1 round key
        return [cipher_key[32 * i: 32 * (i + 1)] for i in range(len(cipher_key) // 32)]

    @staticmethod
    def format_text(text: str):
        hex_str = BitVector(textstring=text).get_bitvector_in_hex()
        i = 0
        while i < len(hex_str):
            if hex_str[i: i + 2] == '0a':
                hex_str = hex_str[0: i] + '0d' + hex_str[i: len(hex_str)]
                i = i + 4
            else:
                i = i + 2
        new_txt = BitVector(hexstring=hex_str).get_bitvector_in_ascii()
        return new_txt

    @staticmethod
    def inv_format_text(hex_str: str):
        i = 0
        while i < len(hex_str):
            if hex_str[i:i + 2] == '0d':
                hex_str = hex_str[0:i] + hex_str[i + 2:len(hex_str)]
            else:
                i = i + 2
        return hex_str
