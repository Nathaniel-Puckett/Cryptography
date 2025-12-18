import numpy as np
from .binary_functions import *

S_BOX = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
         [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
         [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
         [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
         [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
         [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
         [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
         [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
         [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
         [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
         [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
         [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
         [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
         [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
         [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
         [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

MCOLUMN = [[0x02, 0x03, 0x01, 0x01],
           [0x01, 0x02, 0x03, 0x01],
           [0x01, 0x01, 0x02, 0x03],
           [0x03, 0x01, 0x01, 0x02]]


def SPN(plaintext: int, keys: list[int], s_boxes: dict[int], permutation: list[int]) -> int:
    """
    Encrypts using the SPN (Substitution Permutation Network) cipher

    Parameters
    ----------
    plaintext : list[int]
        plaintext represented as bits
    keys : list[list[int]]
        list of keys represented as bits
    s_boxes : dict[list[int]]
        dictionary containing the substitution rule for all S-boxes
    permutation : list[int]
        list of positions representing the rule for permutation

    Returns
    -------
    bits : list[int]
        ciphertext represented as bits
    """

    bits = plaintext
    length = len(permutation)

    rounds = len(keys) - 1
    for round in range(rounds):
        #Add key
        bits ^= keys[round]
        print(f'u^{round+1} : {format(bits, f'0{length}b')}')
        #Apply s-boxes
        for i in range(0, length, 4):
            chunk = (bits >> i) & 0xf
            bits ^= chunk << i
            bits ^= s_boxes[chunk] << i
        print(f'v^{round+1} : {format(bits, f'0{length}b')}')
        #Permute
        if round != rounds-1:
            bits = permute_bits(bits, permutation)
            print(f'w^{round+1} : {format(bits, f'0{length}b')}')
            print()
    #Final key addition
    bits ^= keys[-1]
    
    return bits


def feistel(plaintext: int, keys: list[int], permutation: list[int], func, **kwargs) -> int:
    """
    Encrypts using the Feistel cipher

    Parameters
    ----------
    plaintext : int
        plaintext represented as bits
    keys : list[int]
        list of keys represented as bits
    func : function
        function used to process the right bits and associated key
    permutation : list[int]
        list of positions representing the rule for permutation

    Returns
    -------
    bits : int
        ciphertext represented as bits
    """

    bits = plaintext
    length = len(permutation)

    #Initial permutation
    bits = permute_bits(bits, permutation)
    print(f'p^+ : {format(bits, f'0{length}b')}')
    #Rounds
    rounds = len(keys)
    half = int(length/2)
    for round in range(rounds):
        l_bits = bits >> half
        r_bits = bits ^ (l_bits << half)
        f_bits = func(r_bits, keys[round], **kwargs)
        bits ^= l_bits << half
        bits <<= half
        bits ^= f_bits ^ l_bits
        print(f'r^{round+1} : {format(bits, f'0{length}b')}')
    #Final permutation
    inverse = [0] * len(permutation)
    indexed = True if 0 in permutation else False
    for i in range(len(permutation)):
        if indexed:
            inverse[permutation[i]] = i
        else:
            inverse[permutation[i]-1] = i + 1
    bits = permute_bits(bits, inverse)
    print(f'p^- : {format(bits, f'0{length}b')}')

    return bits


def DES(r_bits: int, key: int, exp: list[int], red: list[list[int]], perm: list[int]) -> int:
    """
    DES (Data Encryption Standard) function, used in Feistel cipher

    Parameters
    ----------
    r_bits : int
        bits from the right hand side of the total bitstring
    key : int
        key represented as bits
    exp : list[int]
        expansion rule (32->48 bits)
    red : list[list[int]]
        reduction rule (48->32 bits) given as a matrix where the first two bits give the row
        and the last four bits give column
    perm : list[int]
        final permutation to use on each set of 8 bits
    
    Returns
    -------
    bits : int
        resulting bits from the function
    """

    #Expansion
    bits = 0
    for val in exp:
        bits ^= ((r_bits & (0x1 << 32-val)) >> 32-val)
        bits <<= 1
    bits >>= 1
    #Add key
    bits ^= key
    #Reduction
    blocks = list()
    for i in range(0, 48, 6):
        row = (bits >> 46-i) & 0x3
        column = (bits >> 42-i) & 0xf
        value = red[row][column]
        blocks.append(value)
    #Permutation
    bits = 0
    for val in permute_list(blocks, perm):
        bits ^= val
        bits <<= 4
    bits >>= 4

    return bits


def example_rule(r_bits: int, key: int) -> int:
    """
    Example of a function used in the Feistel cipher
    
    Parameters
    ----------
    r_bits : int
        bits from the right hand side of the total bitstring
    key : int
        key represented as bits

    Returns
    -------
    new_bits : int
        resulting bits from the function
    """

    new_bits = 0x0
    new_bits ^= (r_bits & 0x8) ^ ((key & 0x1) << 3)
    new_bits ^= ((r_bits & 0x1) << 2) ^ ((key & 0x8) >> 1)
    new_bits ^= ((r_bits & 0x6) ^ (key & 0x6)) >> 1

    return new_bits


def AES_key_schedule(key: int, rotations: list[int], steps: bool = False) -> list[int]:
    """
    AES key schedule for generating subkeys
    
    Parameters
    ----------
    key : int
        key bitstring used to generate subkeys
    rotations : list[int]
        round constants for AES

    Returns
    -------
    subkeys : list[int]
        resulting subkeys from input key
    """

    subkeys = list()
    for round, rotation in enumerate(rotations):
        last_subkey = key if round == 0 else subkeys[-1]
        last_bytes = last_subkey & 0xffffffff
        print(f'w_{3+4*round} : {format(last_bytes, '08x')}') if steps else None

        bits = 0x0
        for i in range(0, 32, 8):
            l_val = (last_bytes >> 28-i) & 0xf
            r_val = (last_bytes >> 24-i) & 0xf
            value = S_BOX[l_val][r_val]
            bits ^= value
            bits <<= 8
        bits >>= 8
        bits = ((bits << 8) ^ (bits >> 24)) & 0xffffffff
        bits ^= rotation
        print(f'g(w_{3+4*round}) : {format(bits, '08x')}') if steps else None

        subkey = 0x0
        for i in range(0, 128, 32):
            subkey_bits = (last_subkey >>96-i) & 0xffffffff
            bits ^= subkey_bits
            subkey ^= (bits << 96-i)
        subkeys.append(subkey)
        print(f'subkey {round} : {format(subkey, '32x')}') if steps else None
        print() if steps else None

    return subkeys


class AES:
    """
    Class for performing AES, 128 bit key length variant
    """

    def __init__(self, plaintext: list[list[int]], subkeys: list[list[int]]) -> None:
        """
        Initialization of class

        Parameters
        ----------
        plaintext : list[list[int]]
            Bytes of plaintext formatted as a 4x4 matrix
        subkeys : list[list[int]]
            Subkeys formatted as a 4x4 matrix
        """

        self.bits = plaintext
        self.keys = subkeys
        self.steps = False

    def __str__(self) -> str:
        """
        Pretty formatting for state

        Returns
        -------
        str_rep : str
            Matrix represented only by byte values and their positon
        """

        str_rep = str()
        for i in range(4):
            for j in range(4):
                str_rep += format(self.bits[i][j], '02x') + (' ' if j != 3 else '')
            str_rep += '\n'
        
        return str_rep

    def add_key(self, index: int) -> None:
        """
        XORs a subkey with the state

        Parameters
        ----------
        index : int
            Index of the subkey to use in list of subkeys
        """

        new_bits = list()
        for i in range(4):
            new_row = list()
            for j in range(4):
                new_byte = self.bits[i][j] ^ self.keys[index][i][j]
                new_row.append(new_byte)
            new_bits.append(new_row)
        
        self.bits = new_bits
        print('Add key\n', self, sep='') if self.steps else None
    
    def shift_rows(self) -> None:
        """
        Shifts rows of the state by 0, 1, 2, & 3 positions respectively
        """

        new_bits = list()
        for i in range(4):
            new_bits.append(permute_list(self.bits[i], [(i)%4, (i+1)%4, (i+2)%4, (i+3)%4]))

        self.bits = new_bits
        print('Shift rows\n', self, sep='') if self.steps else None
        
    def mix_columns(self) -> None:
        """
        Performs matrix multiplication in F_2^8 with the MCOLUMN matrix
        """

        np_bits = np.array(self.bits)
        new_bits = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        for i in range(4):
            np_column = np_bits[:,i]
            for j in range(4):
                byte_jk = 0x00
                for k in range(4):
                    byte_jk ^= multiply_bytes(np_column[k], MCOLUMN[j][k])
                new_bits[j][i] = int(byte_jk)
        
        self.bits = new_bits
        print('Mix columns\n', self, sep='') if self.steps else None
    
    def sub_bytes(self) -> None:
        """
        Substitutes bytes according to the S_BOX table
        """

        new_bits = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        for i in range(4):
            for j in range(4):
                byte_ij = format(self.bits[i][j], '08b')
                l_val, r_val = int(byte_ij[:4], 2), int(byte_ij[4:], 2)
                s_val = S_BOX[l_val][r_val]
                new_bits[i][j] = s_val
        
        self.bits = new_bits
        print('Sub bytes\n', self, sep='') if self.steps else None
    
    def run(self, rounds: int, steps: bool = False) -> None:
        """
        Runs the AES algorithm

        Parameters
        ----------
        rounds : int
            Number of rounds to use
        steps : bool
            Show steps during encryption (default is false)
        """

        self.steps = steps
        print('Plaintext\n', self, sep='') if steps else None

        self.add_key(0)
        for round in range(1, rounds+2):
            self.sub_bytes()
            self.shift_rows()
            self.mix_columns() if round != rounds+1 else None
            self.add_key(round)