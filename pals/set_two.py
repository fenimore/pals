import base64

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB, CBC
from cryptography.hazmat.backends import default_backend

from pals import set_one


class NotDivisibleByKeySize(Exception):
    pass

class BlockTooBig(Exception):
    pass


# Challenge Nine
def implement_pkcs_padding(block, blocksize):
    """
    >>> implement_pkcs_padding(b"YELLOW SUBMARINE", 20)
    b'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'
    """
    if len(block) > blocksize:
        raise BlockTooBig
    if len(block) == blocksize:
        return block
    pad = blocksize - len(block)
    padding = bytearray([pad]*pad)
    return block + padding

def decrypt_cbc_mode(cipher, iv, key):
    """
    >>> f = open("data/ten.txt")
    >>> cipher = base64.b64decode(f.read())
    >>> iv = bytearray([0]*len(b"YELLOW SUBMARINE"))
    >>> decrypt_cbc_mode(cipher, iv, b"YELLOW SUBMARINE")[:32]
    bytearray(b"I\\'m back and I\\'m ringin\\' the bel")
    """
    keysize = len(key)
    if len(cipher) % keysize:
        raise NotDivisibleByKeySize
    prev_block = iv
    message = bytearray()
    idx = 0
    while idx < len(cipher):
        cipher_block = cipher[idx: idx+16]
        decrypted_block = set_one.decrypt_aes_ecb(bytes(cipher_block), key)
        xor_block = set_one.fixed_xor(decrypted_block, prev_block)
        message += xor_block
        prev_block = cipher_block
        idx += 16
    return message

# Challenge Ten
def encrypt_cbc_mode(plaintext, iv, key):
    """
    >>> key = b"YELLOW SUBMARINE"
    >>> iv = bytearray([0]*len(key))
    >>> plaintext = bytearray(b"C8TDY7W0FUP6RZDJAK25HUSKRGYYJAJC0Z83JKPHATGDVBTC9XF53FTD2JIWVSM6EFMP6WU39AEH1BZFW0N1CEYZ48H9RQPA5W548IJSC75NA7EF71XRT2ZIUGQ7SCRJ")
    >>> cipher = encrypt_cbc_mode(plaintext, iv, key)
    >>> decrypt_cbc_mode(cipher, iv, key)
    bytearray(b'C8TDY7W0FUP6RZDJAK25HUSKRGYYJAJC0Z83JKPHATGDVBTC9XF53FTD2JIWVSM6EFMP6WU39AEH1BZFW0N1CEYZ48H9RQPA5W548IJSC75NA7EF71XRT2ZIUGQ7SCRJ')
    """
    keysize = len(key)
    prev_cipher_block = iv
    cipher_text = bytearray()
    idx = 0
    while idx < len(plaintext):
        block = implement_pkcs_padding(plaintext[idx: idx+keysize], 16)
        block = set_one.fixed_xor(block, prev_cipher_block)
        block = set_one.encrypt_ecb_block(bytes(block), key)
        prev_cipher_block = block
        cipher_text += block
        idx += 16
    return cipher_text


if __name__ == "__main__":
    import doctest
    doctest.testmod()
