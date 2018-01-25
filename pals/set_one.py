import doctest
import base64

from itertools import cycle
from math import sqrt

# Challenge 1
def hex_to_base_64(hex):
    """
    >>> hex_to_base_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    return base64.b64encode(bytearray.fromhex(hex))


# Challenge 2
def fixed_xor(a, b):
    """
    >>> fixed_xor("1c0111001f010100061a024b53535009181c", \
        "686974207468652062756c6c277320657965")
    '746865206b696420646f6e277420706c6179'
    >>> fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468")
    """
    first = bytearray.fromhex(a)
    second = bytearray.fromhex(b)
    if len(first) != len(second) or len(first) == 0:
        return None

    result = bytearray()
    for idx in range(0, len(first)):
        result.append(first[idx] ^ second[idx])
    return result.hex()

def xor_hex(message, cipher):
    """
    >>> xor_hex(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", b'X')
    bytearray(b"Cooking MC\\'s like a pound of bacon")
    """
    result = bytearray.fromhex(message.decode())
    for idx in range(0, len(result)):
        result[idx] = result[idx] ^ ord(cipher)
    return result


def frequency_eval(text):
    """
    >>> frequency_eval(b"Hello World")
    0.7153222554962464
    """
    frequencies = {
        b" ": 0.20, b"E": 0.1202, b"T": 0.0910,
        b"A": 0.0812, b"O": 0.0768, b"I": 0.0731,
        b"N": 0.0695, b"S": 0.0628, b"R": 0.0602,
        b"H": 0.0592, b"D": 0.0432, b"L": 0.0398,
        b"U": 0.0288, b"C": 0.0271, b"M": 0.0261,
        b"F": 0.0230, b"Y": 0.0211, b"W": 0.0209,
        b"G": 0.0203, b"P": 0.0182, b"B": 0.0149,
        b"V": 0.0111, b"K": 0.0069, b"X": 0.0017,
        b"Q": 0.0011, b"J": 0.0010,  b"Z": 0.0007,
    }

    result = 0.0
    for char, val in frequencies.items():
        count = text.upper().count(char)
        score = count / len(text)
        result += sqrt(score * val)
    return result


# Challenge 3
def single_byte_xor_cipher(hex_text):
    """
    >>> single_byte_xor_cipher(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    ('X', bytearray(b"Cooking MC\\'s like a pound of bacon"), 0.8998029765969737)
    """
    result = ()
    highest_score = 0
    for letter in range(0, 255):
        message = xor_hex(hex_text, chr(letter))
        score = frequency_eval(message)
        if highest_score < score:
            highest_score = score
            result = (chr(letter), message, score)

    return result


# Challenge Four
def detect_single_character_crypto(path):
    """
    >>> detect_single_character_crypto("data/one/four.txt")
    ('5', bytearray(b\'Now that the party is jumping\\n\'), 0.9514585445439983)
    """
    highest_score = (b'', bytearray(), 0.0)
    with open(path, "rb") as f:
        byte = f.read(1)
        buffer = bytearray()
        while byte:
            if byte == b'\n':
                result = single_byte_xor_cipher(buffer)
                if result[2] > highest_score[2]:
                    highest_score = result

                byte = f.read(1)
                buffer.clear()
                continue
            buffer.append(ord(byte))
            byte = f.read(1)
    return highest_score


# Challenge Five
def repeating_key_xor(cipher, plaintext):
    """
    >>> message = "Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal".encode()
    >>> repeating_key_xor(b"ICE", message)
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    """
    key = cycle(cipher)
    result = bytearray()
    for letter in plaintext:
        result.append(next(key) ^ letter)
    return result.hex()


def hamming_distance(a, b):
    """
    >>> hamming_distance(b"this is a test", b"wokka wokka!!!")
    37
    >>> hamming_distance(bytearray([0b10101]), bytearray([0b10111]))
    1
    """
    if len(a) != len(b):
        raise ValueError("Buffers of different lengths")
    distance = 0
    for idx in range(0, len(a)):
        distance += bin(a[idx] ^ b[idx]).count("1")
    return distance


def population_count(array):
    """
    Get the number of ones in a byte array.
    >>> population_count(bytearray([1]))
    1
    >>> population_count(bytearray([3]))
    2
    >>> population_count(bytearray([1, 3]))
    3
    >>> population_count(bytearray([0b10101]))
    3
    """
    population = 0
    for x in array:
        population += bin(x).count("1")
    return population


def find_keysize(text, max_size=40):
    """
    >>> a = b"HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS"
    >>> b = base64.b64decode(a)
    >>> find_keysize(b, 10)
    5
    """
    size = 0
    lowest_score = None
    for keysize in range(1, max_size):
        a = text[:keysize]
        b = text[keysize:keysize*2]
        score = hamming_distance(a, b) / keysize
        if lowest_score is None:
            lowest_score = score
            size = keysize
        if score < lowest_score:
            lowest_score = score
            size = keysize

    return size

if __name__ == "__main__":
    doctest.testmod()
    f = open("data/one/six.txt", "rb")
    data = base64.b64decode(f.read())
    keysize = find_keysize(data)
    print(keysize)
