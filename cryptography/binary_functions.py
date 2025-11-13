def bin_to_str(bits: list) -> str:
    """
    Converts bits from list type to string type

    Parameters
    ----------
    bits : list
        list of bits to convert

    Returns
    -------
    bit_str : str
        bits formatted as a string
    """

    bit_str = str()
    for bit in bits:
        bit_str += str(bit)

    return bit_str


def str_to_bin(bit_str: str) -> list:
    """
    Converts bits from string type to list type

    Parameters
    ----------
    bit_str : str
        bits formatted as a string

    Returns
    -------
    bits : list
        list of bits
    """

    bits = [0]*len(bit_str)
    for i in range(len(bit_str)):
        bits[i] = int(bit_str)

    return bits


def int_to_bin(num: int, size: int) -> list:
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
    bits : list
        Binary representing number
    """

    bits = [0]*size
    for i in range(1, size+1):
        num, rem = divmod(num, 2)
        bits[-i] = rem
    
    return bits


def bin_to_int(bits):
    """
    Converts a bitstring to its integer representation
    
    Parameters
    ----------
    bits : list
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


def XOR(bits_a: list, bits_b: list) -> list:
    """
    XORs two binary numbers
    
    Parameters
    ----------
    bits_a : list
        First bitstring to add
    bits_b : list
        Second bitstring to add
    
    Returns
    -------
    bits_c : list
        XOR of bits_a and bits_b (mod2)
    """

    bits_c = [(bits_a[i]+bits_b[i])%2 for i in range(len(bits_a))]
    
    return bits_c


def permute(bits: list, permutation: list) -> list:
    """
    Permutes a sequence of bits
    
    Parameters
    ----------
    bits : list
        List of bits to permute
    permutation : list
        Rule used to permute bits (can start at 0 or 1)
    
    Returns
    -------
    permuted_bits : list
        Permuted version of input bits
    """

    permuted_bits = list()
    indexed = True if 0 in permutation else False
    for p in permutation:
        p = p if indexed else p-1
        permuted_bits.append(bits[p])
    
    return permuted_bits


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