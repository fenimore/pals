import base64

from itertools import cycle
from math import sqrt
import heapq

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.backends import default_backend


from pals import set_two

# Challenge 1
def hex_to_base_64(hex):
    """
    >>> hex_to_base_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    return base64.b64encode(bytearray.fromhex(hex))


def fixed_xor(a, b):
    """
    >>> fixed_xor(b"0000000000000000", b"1234567898765432").hex()
    '01020304050607080908070605040302'
    >>> fixed_xor(b"234", b"0")
    """
    if len(a) != len(b):
        return None

    result = bytearray()
    for idx in range(0, len(a)):
        result.append(a[idx] ^ b[idx])
    return result

# Challenge 2
def fixed_xor_hex(a, b):
    """
    >>> fixed_xor_hex("1c0111001f010100061a024b53535009181c", \
        "686974207468652062756c6c277320657965")
    '746865206b696420646f6e277420706c6179'
    """
    first = bytearray.fromhex(a)
    second = bytearray.fromhex(b)
    result = fixed_xor(first, second)
    return result.hex()

def xor_bytes(message, cipher):
    """
    >>> xor_bytes(b'11', b'a')
    bytearray(b'PP')
    """
    result = bytearray(message)
    for idx in range(0, len(result)):
        result[idx] = result[idx] ^ ord(cipher)
    return result


def xor_hex(message, cipher):
    """
    >>> xor_hex(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", b'X')
    bytearray(b"Cooking MC\\'s like a pound of bacon")
    """
    result = bytearray.fromhex(message.decode())
    return xor_bytes(result, cipher)


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


def single_byte_xor(text):
    """
    >>> input = bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    >>> single_byte_xor(input)
    ('X', bytearray(b"Cooking MC\\'s like a pound of bacon"), 0.8998029765969737)
    """
    result = ()
    highest_score = 0
    for letter in range(0, 255):
        message = xor_bytes(text, chr(letter))
        score = frequency_eval(message)
        if highest_score < score:
            highest_score = score
            result = (chr(letter), message, score)

    return result


# Challenge 3
def single_byte_xor_hex(hex_text):
    """
    >>> single_byte_xor_hex(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    ('X', bytearray(b"Cooking MC\\'s like a pound of bacon"), 0.8998029765969737)
    """
    data = bytearray.fromhex(hex_text.decode())
    return single_byte_xor(data)


# Challenge Four
def detect_single_character_crypto(path):
    """
    >>> detect_single_character_crypto("data/four.txt")
    ('5', bytearray(b\'Now that the party is jumping\\n\'), 0.9514585445439983)
    """
    highest_score = (b'', bytearray(), 0.0)
    with open(path, "rb") as f:
        byte = f.read(1)
        buffer = bytearray()
        while byte:
            if byte == b'\n':
                result = single_byte_xor_hex(buffer)
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
    >>> f = open("data/six.txt", "rb")
    >>> data = base64.b64decode(f.read())
    >>> find_keysize(data)
    [(2.6666666666666665, 3), (2.7, 5), (2.7413793103448274, 29)]
    """
    scores = []
    for keysize in range(1, max_size):
        a = text[:keysize]
        b = text[keysize:keysize*2]
        c = text[keysize*2:keysize*3]
        d = text[keysize*3:keysize*4]
        score_a = hamming_distance(a, b)
        score_b = hamming_distance(b, c)
        score_c = hamming_distance(c, d)
        score_d = hamming_distance(a, d)
        score = (score_a + score_b + score_c + score_d) / 4 / keysize
        scores.append((score, keysize))

    return heapq.nsmallest(3, scores)


def transpose_blocks(plaintext, keysize):
    """
    >>> transpose_blocks(b'12341234', 4)
    [b'11', b'22', b'33', b'44']
    """
    blocks = []
    for i in range(0, keysize):
        # NOTE: after second colon is the step-by number <3 python
        blocks.append(plaintext[i::keysize])
    return blocks


# Challenge Six
def break_repeating_key_xor(path):
    """
    >>> break_repeating_key_xor("data/six.txt")[:25]
    bytearray(b"I\\'m back and I\\'m ringin\\' ")
    """
    f = open(path, "rb")
    data = base64.b64decode(f.read())
    keysizes = find_keysize(data)
    highest_score = 0
    probably_key = bytearray()
    for _, size in keysizes:
        key = bytearray()
        scores = 0
        blocks = transpose_blocks(data, size)
        for block in blocks:
            result = single_byte_xor(block)
            key.append(ord(result[0]))
            scores += result[2]
        score = scores / size
        if score > highest_score:
            highest_score = score
            probably_key = key
    cipher = cycle(probably_key)
    result = bytearray()
    for letter in data:
        result.append(next(cipher) ^ letter)
    return result


# Challenge Seven
def decrypt_aes_ecb(plaintext, key):
    """
    >>> f = open("data/seven.txt")
    >>> plaintext = base64.b64decode(f.read())
    >>> decrypt_aes_ecb(plaintext, b"YELLOW SUBMARINE")[:25]
    b"I\'m back and I\'m ringin\' "
    """
    decryptor = Cipher(
        AES(key), ECB(), backend=default_backend()
    ).decryptor()
    return decryptor.update(plaintext) + decryptor.finalize()


# Challenge Seven
def encrypt_ecb_block(message, key):
    """
    >>> encrypt_ecb_block(b"The role of CBC ", b"YELLOW SUBMARINE").hex()
    '4c70bbb7d6585ab30e9600d16705d739'
    >>> encrypt_ecb_block(b"The role", b"YELLOW SUBMARINE").hex()
    'ec64fe6d4dfe16fa78250d9352cb560b'
    """
    if len(message) % len(key) != 0:
        message = set_two.implement_pkcs_padding(message, 16)
    encryptor = Cipher(
        AES(key), ECB(), backend=default_backend()
    ).encryptor()
    return encryptor.update(message) + encryptor.finalize()


# Challenge Eight
def detect_ecb(plaintext_lines):
    """
    >>> f = open("data/eight.txt")
    >>> plaintext = f.readlines()
    >>> detect_ecb(plaintext)[:64]
    'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283'
    """
    for line in plaintext_lines:
        text = bytearray.fromhex(line.strip("\n"))
        seen = []
        for i in range(0, 10):
            if text[16*i:16*i+16] in seen:
                return text.hex()
            else:
                seen.append(text[16*i:16*i+16])


if __name__ == "__main__":
    import doctest
    doctest.testmod()
    print("Set One Complete!")
