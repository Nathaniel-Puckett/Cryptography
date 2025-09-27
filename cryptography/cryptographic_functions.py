import numpy as np

ALPHABET = [['E', 12.2], ['T', 8.8], ['A', 7.9], ['O', 7.2], ['I', 6.8], 
            ['N', 6.5], ['S', 6.1], ['H', 5.9], ['R', 5.8], ['D', 4.1], 
            ['L', 3.9], ['C', 2.7], ['U', 2.7], ['M', 2.3], ['W', 2.3], 
            ['F', 2.1], ['G', 1.9], ['Y', 1.9], ['P', 1.8], ['B', 1.4], 
            ['V', 1.0], ['K', 0.8], ['J', 0.2], ['X', 0.2], ['Z', 0.1],
            ['Q', 0.1]]

def frequency_analysis(text:str):
    frequencies = dict()
    text = text.upper()

    for char in text:
        if char.isalpha():
            if char in frequencies:
                frequencies[char] += 1
            else:
                frequencies[char] = 1
    frequencies = [[key, val] for key, val in frequencies.items()]
    frequencies.sort(key = lambda x: x[1], reverse = True)

    return frequencies

def shift(mode:str, text:str, s:int):
    message = str()
    text = text.lower()
    s = s * (1 if mode == 'e' else -1)

    for char in text:
        x = ord(char) - 97
        e_char = (x+s)%26
        message += chr(e_char+97)
    
    return message

def fa_shift(text:str, num_search:int): #uses frequency analysis on shift
    messages = str()
    frequencies = frequency_analysis(text)

    for frequency in frequencies[:num_search]:
        s = (ord(frequency[0]) - ord('A'))%26
        messages += '\n' + f'Shifted {str(s)} (A = {shift('e', 'A', s).upper()})'
        messages += '\n' + shift('d', text, s) + '\n'

    return messages

def affine(mode:str, text:str, a:int, b:int):
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
            e_char = (a*x + b)%26
        elif mode == 'd':
            e_char = (a_i*(x-b))%26
        message += chr(e_char+97)

    return message

def vigenere(mode:str, text:str, key:str):
    message = str()
    text = text.lower()
    key_vals = [ord(char)-97 for char in key]

    for i in range(len(text)):
        x = ord(text[i]) - 97
        k = key_vals[i % len(key)] * (1 if mode == 'e' else -1)
        e_char = (x+k)%26
        message += chr(e_char+97)

    return message

def hill(mode:str, text:str, matrix):
    message = str()
    text = text.lower()
    m = len(matrix)

    if mode == 'd':
        det = int(round(np.linalg.det(matrix), 0))
        det_inv = pow(det, -1, 26)
        matrix = (np.linalg.inv(matrix)*det*det_inv)%26

    for i in range(0, len(text), m):
        v_a = np.array([[ord(char)-97] for char in text[i:i+m]])
        v_b = np.matmul(matrix, v_a)
        for b in v_b:
            message += chr(int(round(b[0], 0))%26 + 97)

    return message

def permutation(mode:str, text:str, ordering:list):
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

def autokey(mode:str, text:str, key:int):
    message = str()
    text = text.lower()
    s = key

    for char in text: 
        x = ord(char) - 97
        e_char = (x + (s if mode == 'e' else -s))%26
        message += chr(e_char+97)
        s = (x if mode == 'e' else e_char)

    return message

def bf_autokey(text:str): #uses brute force on autokey
    messages = str()
    text = text.lower()

    for key in range(26):
        attempt = autokey('d', text, key)
        messages += '\n' + f'{chr(key+97)} : {attempt}' + '\n'

    return messages