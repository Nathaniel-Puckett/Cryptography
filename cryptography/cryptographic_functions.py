import numpy as np
from .binary_functions import *

F_ALPHABET = [['E', 12.2], ['T', 8.8], ['A', 7.9], ['O', 7.2], ['I', 6.8], 
              ['N', 6.5], ['S', 6.1], ['H', 5.9], ['R', 5.8], ['D', 4.1], 
              ['L', 3.9], ['C', 2.7], ['U', 2.7], ['M', 2.3], ['W', 2.3], 
              ['F', 2.1], ['G', 1.9], ['Y', 1.9], ['P', 1.8], ['B', 1.4], 
              ['V', 1.0], ['K', 0.8], ['J', 0.2], ['X', 0.2], ['Z', 0.1],
              ['Q', 0.1]]

S_ALPHABET = [['A', 7.9], ['B', 1.4], ['C', 2.7], ['D', 4.1], ['E', 12.2], 
              ['F', 2.1], ['G', 1.9], ['H', 5.9], ['I', 6.8], ['J', 0.2], 
              ['K', 0.8], ['L', 3.9], ['M', 2.3], ['N', 6.5], ['O', 7.2], 
              ['P', 1.8], ['Q', 0.1], ['R', 5.8], ['S', 6.1], ['T', 8.8], 
              ['U', 2.7], ['V', 1.0], ['W', 2.3], ['X', 0.2], ['Y', 1.9], 
              ['Z', 0.1]]


def frequency_analysis(text: str) -> list[list]:
    """
    Computes the frequency of alphabetical characters for a given string.

    Parameters
    ----------
    text : str
        Text to analyze

    Returns
    -------
    frequencies : list[list]
        Frequencies of letters sorted from most to least common
    """

    frequencies = dict()
    text = text.upper()

    for char in text:
        if char.isalpha():
            if char in frequencies:
                frequencies[char] += 1
            else:
                frequencies[char] = 1
    for letter in S_ALPHABET:
        if letter[0] not in frequencies:
            frequencies[letter[0]] = 0
    
    frequencies = [[key, val] for key, val in frequencies.items()]
    frequencies.sort(key = lambda x: x[1], reverse = True)

    return frequencies


def index_coincidence(text: str) -> float:
    """
    Finds the index of coincidence for some text

    Parameters
    ----------
    text : str
        Text to analyze

    Returns
    -------
    total : float
        Index of coincidence of string
    """

    frequencies = frequency_analysis(text)
    n = len(text)

    total = sum([(f[1]**2 - f[1]) / (n**2 - n) for f in frequencies])
    
    return total


def vigenere_analysis(text: str, key_len: int):
    """
    Finds possible keys for ciphertext encrypted with the vigenere cipher

    Parameters
    ----------
    text : str
        Text to analyze
    key_len : int
        (Guessed) length of key, can be found through the Kasiski test

    Returns
    -------
    best_list : list[list[list]]
        List of each possible key value with index of coincidence
    best_guess : str
        String with all the most likely key candidates
    """

    y_list = [[] for i in range(key_len)]
    best_list = []
    best_guess = ''

    for i, char in enumerate(text):
        y_list[i%key_len].append(char)
    
    for index, y_i in enumerate(y_list):
        y_text = ''.join(y_i)
        y_frequencies = frequency_analysis(y_text)
        y_frequencies.sort(key = lambda x: x[0])
        n = len(y_text)

        ic_list = []
        for i in range(26):
            m_i = 0
            for j, alph in enumerate(S_ALPHABET):
                m_i += (alph[1] * y_frequencies[(i+j)%26][1]) / n
            ic_list.append([m_i, chr(i+97)])
        ic_list.sort(key = lambda x: x[0], reverse=True)

        best_list.append([f'Possible values for the key at {index}', ic_list[:3]])
        best_guess += ic_list[0][1]

    return best_list, best_guess


def shift(mode: str, text: str, s: int) -> str:
    """
    Encrypts/decrypts text using the shift cipher

    Parameters
    ----------
    mode : str
        'e' for encryption, 'd' for decryption
    text : str
        Text to analyze
    s : int
        Amount to shift by

    Returns
    -------
    message : str
        Plaintext/ciphertext of input text
    """

    message = str()
    text = text.lower()
    s = s * (1 if mode == 'e' else -1)

    for char in text:
        x = ord(char) - 97
        e_char = (x+s) % 26
        message += chr(e_char + 97)
    
    return message


def affine(mode: str, text: str, a: int, b: int) -> str:
    """
    Encrypts/decrypts text using the Affine cipher

    Parameters
    ----------
    mode : str
        'e' for encryption, 'd' for decryption
    text : str
        Text to analyze
    a : int
        Multiplicative part of the key, must have an inverse
    b : int
        Additive part of the key

    Returns
    -------
    message : str
        Plaintext/ciphertext of input text
    """

    message = str()
    text = text.lower()

    try:
        a_i = pow(a, -1, 26)
    except:
        print("Invalid input for (a). (a) must be coprime with 26.")
        return None

    for char in text:
        x = ord(char) - 97
        if mode == 'e':
            e_char = (a*x + b) % 26
        elif mode == 'd':
            e_char = (a_i * (x-b)) % 26
        message += chr(e_char + 97)

    return message


def vigenere(mode: str, text: str, key: str) -> str:
    """
    Encrypts/decrypts text using the Vigenere cipher

    Parameters
    ----------
    mode : str
        'e' for encryption, 'd' for decryption
    text : str
        Text to analyze
    key : str
        Key word to use for encryption/decryption

    Returns
    -------
    message : str
        Plaintext/ciphertext of input text
    """

    message = str()
    text = text.lower()
    key_vals = [ord(char)-97 for char in key]

    for i in range(len(text)):
        x = ord(text[i]) - 97
        k = key_vals[i % len(key)] * (1 if mode == 'e' else -1)
        e_char = (x+k) % 26
        message += chr(e_char + 97)

    return message


def hill(mode: str, text: str, matrix) -> str:
    """
    Encrypts/decrypts text using the Hill cipher

    Parameters
    ----------
    mode : str
        'e' for encryption, 'd' for decryption
    text : str
        Text to analyze
    matrix : numpy array
        Square invertible matrix used as key

    Returns
    -------
    message : str
        Plaintext/ciphertext of input text
    """

    message = str()
    text = text.lower()
    m = len(matrix)

    if mode == 'd':
        det = int(round(np.linalg.det(matrix), 0))
        det_inv = pow(det, -1, 26)
        matrix = (np.linalg.inv(matrix)*det*det_inv) % 26

    for i in range(0, len(text), m):
        v_a = np.array([[ord(char)-97] for char in text[i:i+m]])
        v_b = np.matmul(matrix, v_a)
        for b in v_b:
            message += chr(int(round(b[0], 0))%26 + 97)

    return message


def permutation(mode: str, text: str, ordering: list) -> str:
    """
    Encrypts/decrypts text using the permutation cipher

    Parameters
    ----------
    mode : str
        'e' for encryption, 'd' for decryption
    text : str
        Text to analyze
    ordering : list
        New ordering of letters from plaintext

    Returns
    -------
    message : str
        Plaintext/ciphertext of input text
    """

    message = str()
    text = text.lower()
    m = len(ordering)

    ordering_matrix = np.zeros([m, m])
    for i in range(m):
        ordering_matrix[ordering[i], i] = 1

    if mode == 'd':
        ordering_matrix = np.linalg.matrix_transpose(ordering_matrix)

    for i in range(0, len(text), m):
        v_a = np.array([[ord(char)-97] for char in text[i:i+m]])
        v_b = np.matmul(ordering_matrix, v_a)
        for b in v_b:
            message += chr(int(round(b[0], 0))%26 + 97)

    return message


def autokey(mode: str, text: str, key: int) -> str:
    """
    Encrypts/decrypts text using the autokey cipher

    Parameters
    ----------
    mode : str
        'e' for encryption, 'd' for decryption
    text : str
        Text to analyze
    key : int
        Key for shifting first letter

    Returns
    -------
    message : str
        Plaintext/ciphertext of input text
    """

    message = str()
    text = text.lower()
    s = key

    for char in text: 
        x = ord(char) - 97
        e_char = (x + (s if mode == 'e' else -s)) % 26
        message += chr(e_char + 97)
        s = (x if mode == 'e' else e_char)

    return message


def SPN(plaintext: list, keys: list[list], s_boxes: dict[list], permutation: list) -> list:
    """
    Encrypts using the SPN (Substitution Permutation Network) cipher
    #need to add decryption

    Parameters
    ----------
    plaintext : list
        plaintext represented as bits
    keys : list[list]
        list of keys represented as bits
    s_boxes : dict[list]
        dictionary containing the substitution rule for all S-boxes
    permutation : list
        list of positions representing the rule for permutation

    Returns
    -------
    bits : list
        ciphertext represented as bits
    """

    bits = plaintext
    s_len = len(list(s_boxes)[0])

    rounds = len(keys) - 1
    for round in range(rounds):
        #Add key
        bits = XOR(keys[round], bits)
        print(f'u^{round+1} : {bin_to_str(bits)}')
        #Apply s-boxes
        for i in range(0, len(bits), s_len):
            chunk = tuple(bits[i:i+s_len])
            bits[i:i+s_len] = s_boxes[chunk]
        print(f'v^{round+1} : {bin_to_str(bits)}')
        #Permute
        if round != rounds-1:
            bits = permute(bits, permutation)
            print(f'w^{round+1} : {bin_to_str(bits)}')
            print()
    #Final key addition
    bits = XOR(keys[-1], bits)
    
    return bits


def feistel(plaintext: list, keys: list, permutation: list, func, **kwargs) -> list:
    """
    Encrypts using the Feistel cipher
    #need to add decryption

    Parameters
    ----------
    plaintext : list
        plaintext represented as bits
    keys : list[list]
        list of keys represented as bits
    func : function
        function used to process the right bits and associated key
    permutation : list
        list of positions representing the rule for permutation

    Returns
    -------
    bits : list
        ciphertext represented as bits
    """

    bits = plaintext

    #Initial permutation
    bits = permute(bits, permutation)
    print(f'p : {bin_to_str(bits)}')
    #Rounds
    rounds = len(keys)
    half = int(len(bits)/2)
    for round in range(rounds):
        l_bits = bits[:half]
        r_bits = bits[half:]
        f_bits = func(r_bits, keys[round], **kwargs)
        r_bits = XOR(f_bits, l_bits)
        bits = bits[half:] + r_bits
        print(f'r^{round+1} : {bin_to_str(bits)}')
    #Final permutation
    inverse = [0] * len(permutation)
    indexed = True if 0 in permutation else False
    for i in range(len(permutation)):
        if indexed:
            inverse[permutation[i]] = i
        else:
            inverse[permutation[i]-1] = i + 1
    bits = permute(bits, inverse)
    print(f'p^-1 : {bin_to_str(bits)}')

    return bits


def DES(r_bits, key, exp, red, perm):
    """
    DES (Data Encryption Standard) function, used in Feistel cipher

    Parameters
    ----------
    r_bits : list
        bits from the right hand side of the total bitstring
    key : list
        key represented as bits
    exp : list
        expansion rule (32->48 bits)
    red : list[list]
        reduction rule (48->32 bits) given as a matrix where the first two bits give the row
        and the last four bits give column
    perm : list
        final permutation to use on each set of 8 bits
    
    Returns
    -------
    f_bits : list
        resulting bits from the function
    """

    #Expansion
    f_bits = list()
    for val in exp:
        f_bits.append(r_bits[val-1])
    #Add key
    f_bits = XOR(f_bits, key)
    #Reduction
    new_bits = list()
    for i in range(0, len(f_bits), 6):
        row, column = tuple(f_bits[i:i+2]), tuple(f_bits[i+2:i+6])
        r_val = bin_to_int(row)
        c_val = bin_to_int(column)
        num = red[r_val][c_val]
        reduced_bits = int_to_bin(num, 4)
        new_bits.append(reduced_bits)
    #Permutation
    f_bits = list()
    for block in permute(new_bits, perm):
        f_bits.extend(block)

    return f_bits


def example_rule(r_bits: list, key: list) -> list:
    """
    Example of a function used in the Feistel cipher
    (Note that all functions must use the same number and type of inputs/outputs)
    
    Parameters
    ----------
    r_bits : list
        bits from the right hand side of the total bitstring
    key : list
        key represented as bits

    Returns
    -------
    f_bits : list
        resulting bits from the function
    """

    f_bits = list()
    for i in range(len(key)):
        val = (r_bits[i]+key[i]) % 2
        f_bits.append(val)
    
    return f_bits


def bf_shift(text: str) -> str:
    """
    Uses a brute force attack on the shift cipher

    Parameters
    ----------
    text : str
        Text to analyze

    Returns
    -------
    messages : str
        Possible plaintexts of input text
    """

    messages = str()
    frequencies = frequency_analysis(text)

    for frequency in frequencies:
        s = (ord(frequency[0])-ord('A')) % 26
        messages += '\n' + f'Shifted {str(s)} (A = {shift('e', 'A', s).upper()})'
        messages += '\n' + shift('d', text, s) + '\n'

    return messages


def bf_autokey(text: str) -> str:
    """
    Uses a brute force attack on the autokey cipher

    Parameters
    ----------
    text : str
        Text to analyze

    Returns
    -------
    messages : str
        Possible plaintexts of input text
    """

    messages = str()
    text = text.lower()

    for key in range(26):
        attempt = autokey('d', text, key)
        messages += '\n' + f'{chr(key + 97)} : {attempt}' + '\n'

    return messages