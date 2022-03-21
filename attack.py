# -*- coding: utf-8 -*-
""" CNT5410 -- Assignment 1: Passwords -- attack.py

# This file tests the attacks
"""

import os

import utils
import crypto
import rainbow

import random
import sys



"""
## Simple exhaustive attack.

    Inputs:
        pc: performance counter (PerfCounter),
        next_fn: next candidate password function,
        pwhash_fn: compute password hash function,
        pwhash_list: the list of password hashes we want to invert (find the plaintext password for)
        
    Outputs:
        results: array of length len(pwhash_list) containing the matching passwords (or None)
"""
def simple_exhaustive_attack(pc, pw_gen, pwhash_fn, pwhash_list):
    results = [None for i in range(0, len(pwhash_list))]

    while pw_gen:

        try:
            candidate_pw = next(pw_gen)
        except StopIteration:
            break

        # compute the password hash
        candidate_pwhash = pwhash_fn(candidate_pw)
        pc.inc()

        for i, pwhash in enumerate(pwhash_list):
            assert len(pwhash) == len(candidate_pwhash), 'Hash lengths do not match.'
            if results[i] is not None:
                continue
            if pwhash == candidate_pwhash:
                results[i] = candidate_pw

        if None not in results:
            break

    return results


## extract password hash list
def get_pwhash_list(pwlist_fp):
    pwlist_obj = utils.read_json(pwlist_fp)
    pwhash_list = []

    for i, pwitem in enumerate(pwlist_obj):
        pwhash_list.append(pwitem['hash'])

    return pwhash_list, pwlist_obj


def test_rainbow_attack(rb_fp, pwlist_fp, num_chains, k, length, pwhash_length, verb=False):
    rseed = 0xA5A5A5A5
    r = random.Random(rseed)

    char_list = 'abcdefghijklmnopqrstuvwxyz0123456789'

    pwhash_fn = lambda p: crypto.truncated_sha2_hex_digest(p, pwhash_length)
    reduce_fn = lambda i, h: crypto.reduce_family(i, h, length)
    random_candidates_fn = lambda : crypto.get_random_candidate(r, char_list, length)

    pc = utils.PerfCounter()
    pc.start()
    rainbow.build_rainbow(pc, rb_fp, num_chains, k, pwhash_fn, reduce_fn, random_candidates_fn)
    pc.stop()

    hashes, duration = pc.perf()
    print('Built rainbow table with {} chains of length {} in {:.1f} seconds (total hashes: {}, {:.1f} h/s)'.format(num_chains, k, duration, hashes, float(hashes)/duration))

    pwhash_list, pwlist_obj = get_pwhash_list(pwlist_fp)

    pc = utils.PerfCounter()
    pc.start()
    pwres = rainbow.lookup_rainbow(pc, rb_fp, k, pwhash_fn, reduce_fn, pwhash_list, verbose=verb)
    pc.stop()

    print_attack_perf(pc, pwres, pwlist_obj, 'Lookups over rainbow table ')

    return pwres, pwlist_obj

## print performance of the attack
def print_attack_perf(pc, pwres, pwlist_obj, desc='Attack'):
    successes = len([pw for pw in pwres if pw is not None])

    hashes, duration = pc.perf()
    print('{} found {} passwords in {:.1f} seconds (total hashes: {} --- {:.1f} h/s)'.format(desc, successes, duration, hashes, float(hashes) / duration))

    for i, pwitem in enumerate(pwlist_obj):
        user = pwitem['user']
        pwhash = pwitem['hash']

        pw = pwres[i]
        pwstr = '?' if pw is None else pw
        print('\tFor user {} with pwhash: {} -> password: {}'.format(user, pwhash, pwstr))

    print('Attack success rate: {}%!'.format(int(float(successes) / len(pwlist_obj)*100)))
    print('')


# test for the simple exhaustive attack
def test_simple_exhaustive_attack(pwlist_fp, next_fn, pwhash_fn, shortdesc):

    pwhash_list, pwlist_obj = get_pwhash_list(pwlist_fp)

    pc = utils.PerfCounter()
    pc.start()
    pwres = simple_exhaustive_attack(pc, next_fn, pwhash_fn, pwhash_list)
    pc.stop()

    print_attack_perf(pc, pwres, pwlist_obj, 'Simple {} attack'.format(shortdesc))

    return pwres, pwlist_obj


## TODO: Problem 4.3 --- (20 pts + 5 pts [bonus]) ##
"""
## Bob's custom pwhash attack.

    Inputs:
        pc: performance counter (PerfCounter),
        char_list: list of characters,
        length: length of the passwords,
        pwlist_obj: the object of password hashes

    Outputs:
        results: array of length len(pwlist_obj) containing the matching passwords (or None)
"""
def bobs_custom_pwhash_attack(pc, char_list, length, pwlist_obj):

    results = [None for i in range(0, len(pwlist_obj))]
    assert (length % 2 == 0), 'Length must be a multiple of 2'

    pwhash_fn = crypto.bobs_custom_pw_hash

    ## TODO ##
    ## Insert your code here
    import operator
    pwhash_length = len(pwlist_obj[0]['hash'])          # Get whole password hash length
    l = int(pwhash_length/3)                            # Get length of a one hash part 
    pwhash_fn_p1_truncated = lambda p: crypto.truncated_sha2_hex_digest(p + '-p1', 6)       # Define hash function for p1
    pwhash_fn_p2_truncated = lambda p: crypto.truncated_sha2_hex_digest(p + '-p2', 6)       # Define hash function for p2
    hash_p1, hash_p2, salt_c, salts, pwhashs = [], [], [], [], []   # Store all the p1, p2's to bruteforce toghether
    # raise NotImplementedError()

    for i, pwitem in enumerate(pwlist_obj):
        user = pwitem['user']
        salt = pwitem['salt']
        pwhash = pwitem['hash']

        ## TODO ##
        ## Insert your code here
        hash_p1 += [pwhash[:l]]          # Get hash of p1 from given hash as a list
        hash_p2 += [pwhash[l:2*l]]       # Get hash of p2 from given hash as a list
        salt_c.append(pwhash[2*l:])         # Get last hash part from given hash as a list (not useful)
        salts.append(salt)                  # Store salts
        pwhashs.append(pwhash)              # Store password hashes
        if(i == len(pwlist_obj) - 1):       # This condition only true in last iteration.
            pw_gen_1 = crypto.candidate_bf_generator(char_list, int(length/2))    
            p1 = simple_exhaustive_attack(pc, pw_gen_1, pwhash_fn_p1_truncated, hash_p1) # Brute force attack to find p1 together
            pw_gen_2 = crypto.candidate_bf_generator(char_list, int(length/2))
            p2 = simple_exhaustive_attack(pc, pw_gen_2, pwhash_fn_p2_truncated, hash_p2) # Brute force attack to find p2 together
            results = list(map(operator.add, p1, p2))          # Concatenate to form p

            # This loop runs in last iteration. This is not neccesary for crack passswords
            for j in range(len(pwlist_obj)):             # To check pwhash_fn(salt, password) == pwhash
                password, salt, pwhash = results[j], salts[j], pwhashs[j]  
                assert pwhash_fn(salt, password) == pwhash
        pc.inc()
        
    return results


# test for Bob's custom pwhash attack
def test_bobs_custom_pwhash_attack(pwlist_fp, char_list, length, shortdesc):

    pwhash_list, pwlist_obj = get_pwhash_list(pwlist_fp)

    pc = utils.PerfCounter()
    pc.start()
    pwres = bobs_custom_pwhash_attack(pc, char_list, length, pwlist_obj)
    pc.stop()

    print_attack_perf(pc, pwres, pwlist_obj, 'Bob custom pwhash attack'.format(shortdesc))

    return pwres, pwlist_obj




def main():

    assert len(sys.argv) == 2, 'Incorrect number of arguments!'
    p_split = sys.argv[1].split('problem')
    assert len(p_split) == 2 and p_split[0] == '', 'Invalid argument {}.'.format(sys.argv[1])
    problem = p_split[1]

    assert problem.isdigit(), 'Invalid argument {}.'.format(sys.argv[1])
    problem = int(problem)

    data_fp = os.path.join(os.getcwd(), 'data')
    assert os.path.exists(data_fp), 'Can''t find data!'


    import tempfile
    import shutil

    complex4_pwlist_fp = os.path.join(data_fp, 'complex4-dbdump.json')
    simple_pwlist_fp = os.path.join(data_fp, 'simple-dbdump.json')

    lc_alphanum_char_list = 'abcdefghijklmnopqrstuvwxyz0123456789'

    pwhash_length = 12
    pw_length = 4

    def pwhash_fn(p):
        return crypto.truncated_sha2_hex_digest(p, pwhash_length)

    test_workdir = tempfile.mkdtemp()

    if problem == 0:
        pw_gen = crypto.candidate_bf_generator(lc_alphanum_char_list, pw_length)
        utils.test_with_cleanup(
                    lambda: test_simple_exhaustive_attack(simple_pwlist_fp, pw_gen, pwhash_fn, 'bruteforce 4-ch alphanum'),
                    lambda: shutil.rmtree(test_workdir))

    elif problem == 1:
        suffix_list = '0123456789.,:;[]{}|?<>_+-)(*&^%$#@!~'
        words = utils.get_words()
        pw_gen = crypto.candidate_dict_generator(words, suffix_list)

        test_workdir = tempfile.mkdtemp()
        utils.test_with_cleanup(
                    lambda: test_simple_exhaustive_attack(simple_pwlist_fp, pw_gen, pwhash_fn, 'dictionary attack'),
                    lambda: shutil.rmtree(test_workdir))

    elif problem == 2 or problem == 3:

        # default values: num_chains = 100000, k=16
        num_chains = 100000
        k = 16

        rb_fp = os.path.join(test_workdir, 'rainbow-table.json')

        if problem == 2:
            utils.test_with_cleanup(                                     # replace with verb=True to show false alarms
                    lambda: test_rainbow_attack(rb_fp, simple_pwlist_fp, num_chains, k, pw_length, pwhash_length, verb=False),
                    lambda: shutil.rmtree(test_workdir))

        if problem == 3:
            utils.test_with_cleanup(
                    lambda: test_rainbow_attack(rb_fp, complex4_pwlist_fp, num_chains, k, pw_length, pwhash_length, verb=False),
                    lambda: shutil.rmtree(test_workdir))

    elif problem == 4:
        ## TODO: uncomment as needed (Problem 4.3)
        pw_length = 4
        # pw_length = 6
        # pw_length = 8
        bob_pwlist_fp = os.path.join(data_fp, 'bob{}-dbdump.json'.format(pw_length))

        utils.test_with_cleanup(
                    lambda: test_bobs_custom_pwhash_attack(bob_pwlist_fp, lc_alphanum_char_list, pw_length, 'bobs'),
                    lambda: shutil.rmtree(test_workdir))

    else:
        assert False, 'Invalid problem number {}.'.format(problem)

 ## run the tests               
if __name__ == '__main__':
    main()