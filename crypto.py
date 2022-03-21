# -*- coding: utf-8 -*-
""" CNT5410 -- Assignment 1: Passwords -- crypto.py
"""

import binascii
import random

from Crypto.Hash import SHA256

## hash functions

# SHA256 digest
def sha2(x):
    return SHA256.new(x.encode('utf-8')).digest()

# raw SHA256 digest
def raw_sha2(x):
    return SHA256.new(x).digest()

# hex of SHA256 digest
def sha2_hex_digest(x):
    return binascii.hexlify(sha2(x))

# hex of truncated SHA256 digest
def truncated_sha2_hex_digest(x, tsz):
    return binascii.hexlify(sha2(x)[:tsz]).decode("utf-8")

""" 
## Implementation of Bob's custom pw hash function
    
    Inputs:
        salt: the salt (string),
        pw: the password (string)

    Notes:
        the password length must be a multiple of 2!

    Outputs:
        the password hash (hexadecimal string)
"""
def bobs_custom_pw_hash(salt, pw):
    length = len(pw)
    assert (length % 2) == 0, 'Passwords must have even length!'
    pw_p1 = pw[0:int(length/2)]
    th1 = truncated_sha2_hex_digest(pw_p1 + '-p1', 6)
    pw_p2 = pw[int(length/2):]
    th2 = truncated_sha2_hex_digest(pw_p2 + '-p2', 6)

    iterated_hash = raw_sha2((salt + '---bob''s super secure custom pw hash v1').encode('utf-8'))
    for i in range(0, 10000):
        iterated_hash = raw_sha2(iterated_hash)

    return th1 + th2 + binascii.hexlify(iterated_hash[:6]).decode('utf-8')


""" 
## Reduction function family

    Inputs:
        i: the index of the function within the family,
        hash_hex: the (hexadecimal string) hash to reduce,
        length: the desired length of the reduced strings (number of characters)

    Notes:
        the hash to be reduced must be at least twice as long as the desired reduced string

    Outputs:
        the reduced string
"""
def reduce_family(i, hash_hex, length):
    char_list = 'abcdefghijklmnopqrstuvwxyz0123456789'

    assert len(hash_hex) >= 2*length

    hash_bytes = list(bytearray(binascii.unhexlify(hash_hex)))
    random.Random(i).shuffle(hash_bytes)

    l = length
    for i in range(0, length):
        if (hash_bytes[-(1+i)] % len(char_list)) == 0:
            l -= 1
        else:
            break

    res = []
    for j in range(0, l):
        idx = hash_bytes[j] % len(char_list)
        res.append(char_list[idx])
    return ''.join(res)



""" 
## Return a random password

    Inputs:
        r: an instance of a Random object (RNG),
        char_list: the list of valid characters,
        length: the desired length of password

    Outputs:
        the password
"""
def get_random_candidate(r, char_list, length):
    candidate = ''
    for i in range(0, length):
        idx = r.randint(0, len(char_list)-1)
        assert idx < len(char_list)
        candidate += char_list[idx]
    return candidate


## get password candidate for a bruteforce password generator
def get_candidate_bf(counter, char_list):
    if counter == -1:
        return ''

    c = counter
    lc = len(char_list)
    candidate = []
    while c >= 0:
        idx = c % lc
        candidate.append(char_list[idx])
        c -= idx
        if c == 0:
            break
        c = int(c / lc)-1
    return ''.join(reversed(candidate))

## get password candidate for a dictionary-based password generator
def get_candidate_dict(counter, words, suffix):
    lw = len(words)
    if counter < lw:
        return words[counter]
    c = counter - lw
    widx = c % lw
    sidx = int(c / lw)
    return words[widx] + suffix[sidx]


""" 
## Generator of bruteforce passwords

    Inputs:
        char_list: the list of valid characters,
        max_length: the maximum length of password

    Outputs:
        the (candidate) password
"""
def candidate_bf_generator(char_list, max_length):
    counter = -1
    lc = len(char_list)

    num_candidates = 0
    for l in range(1, max_length + 1):
        num_candidates += lc ** l

    while True:
        yield get_candidate_bf(counter, char_list)

        if counter >= num_candidates-1:
            return

        counter += 1


## TODO: Problem 1.1 --- (10 pts) ##
""" 
## Generator of dictionary-based passwords
    Pattern is: <w> or <w><s>, where <w> denotes a word and <s> denotes a suffix character

    Inputs:
        words: the list of words in the dictionary,
        suffix: the list of suffix characters

    Outputs:
        the (candidate) password
"""
def candidate_dict_generator(words, suffix):
    counter = 0
    lw = len(words)
    lc = len(suffix)

    ## TODO ##
    ## Insert your code here
    ## hint: use get_candidate_dict()
    candidate_count = lw + lw*lc            # Because we guess passwords of the form w or w||s
    for counter in range(candidate_count):  # Counter can get numbers between 0 to cadidate_count-1
        yield get_candidate_dict(counter, words, suffix)
    else:
        return
    # raise NotImplementedError()