"""
Contains bit manipulation functions
"""

def int_to_bin(num: int, size: int) -> list[int]:
    """
    Converts an integer into its binary representation
    
    Parameters
    ----------
    num : int
        The integer to convert
    size : int
        Size of binary
    
    Returns
    -------
    bits : list[int]
        Binary representing number
    """

    bits = [0]*size
    for i in range(1, size+1):
        num, rem = divmod(num, 2)
        bits[-i] = rem
    
    return bits


def bin_to_int(bits: list[int]) -> int:
    """
    Converts a bitstring to its integer representation
    
    Parameters
    ----------
    bits : list[int]
        The bitstring to convert to an integer
    
    Returns
    -------
    num : int
        The integer representation of the bitstring
    """

    num = 0
    for i in range(len(bits)):
        num += bits[-i-1] * (2**i)
    
    return num


def XOR(bits_a: list[int], bits_b: list[int]) -> list[int]:
    """
    XORs two binary numbers
    
    Parameters
    ----------
    bits_a : list[int]
        First bitstring to add
    bits_b : list[int]
        Second bitstring to add
    
    Returns
    -------
    bits_c : list
        XOR of bits_a and bits_b (mod2)
    """

    bits_c = [(bits_a[i]+bits_b[i])%2 for i in range(len(bits_a))]
    
    return bits_c


def permute_bits(bits: int, permutation: list[int]) -> int:
    """
    Permutes a sequence of bits
    
    Parameters
    ----------
    bits : int
        Bits to permute
    permutation : list[int]
        Rule used to permute bits (can start at 0 or 1)
    
    Returns
    -------
    permuted_bits : int
        Permuted version of input bits
    """

    length = len(permutation)
    bit_str = format(bits, f'0{length}b')

    permuted_bits = str()
    zero = True if 0 in permutation else False
    for p in permutation:
        p = p if zero else p-1
        permuted_bits += bit_str[p]
    permuted_bits = int(permuted_bits, 2)
    
    return permuted_bits


def permute_list(in_list: list, permutation: list[int]) -> list:
    """
    Permutes a list of values
    
    Parameters
    ----------
    in_list : list
        List to permute
    permutation : list[int]
        Rule used to permute list (can start at 0 or 1)
    
    Returns
    -------
    permuted_list : list
        Permuted version of input list
    """

    permuted_list = list()
    indexed = True if 0 in permutation else False
    for p in permutation:
        p = p if indexed else p-1
        permuted_list.append(in_list[p])
    
    return permuted_list


def multiply_bytes(in_a: int, in_b: int) -> int:
    """
    Multiplies two bytes over F_2^8
    Algorithm taken from the post below:
    https://stackoverflow.com/questions/70261458/how-to-perform-addition-and-multiplication-in-f-28
    
    Parameters
    ----------
    in_a : int (<256)
        Input byte A
    in_b : int (<256)
        Input byte B
    
    Returns
    -------
    result : int (<256)
        Result of the multiplication of in_a and in_b over F_2^8
    """
    
    byte_a = int(in_a)
    byte_b = int(in_b)
    p = 0b100011011

    result = 0
    for i in range(8):
        result = result << 1
        if result & 0b100000000:
            result = result ^ p
        if byte_b & 0b010000000:
            result = result ^ byte_a
        byte_b = byte_b << 1

    return result