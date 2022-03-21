# -*- coding: utf-8 -*-
""" CNT5410 -- Assignment 1: Passwords -- rainbow.py
"""

import sys
import utils

"""
## Build rainbow table.

    Inputs:
        pc: performance counter (PerfCounter),
        next_fn: next candidate password function,
        out_fp: output filepath,
        num_chains: number of chains to compute,
        k: length of each chain,
        pwhash_fn: compute password hash function,
        reduce_fn: reduce function family,
        random_candidates_fn: random password candidates function

    Outputs:
        None
"""
def build_rainbow(pc, out_fp, num_chains, k, pwhash_fn, reduce_fn, random_candidates_fn):

    table = {}

    ## TODO: Problem 3.4 (5 pts) ##
    ## Put your code here to avoid duplicating start points
    startpoints = {}    # To store boolean value with startpoint keys. I used dictonary here because search time complexity is O(1)    

    sys.stdout.write('Building rainbow table')
    for i in range(0, num_chains):
        # build chain i
        startpoint = random_candidates_fn()

        ## TODO: Problem 3.4 (5 pts) ##
        ## Put your code here to avoid duplicating start points
        if i > 36 ** 4: # To make sure i is less than number of possible passwords.
            break       # If yes break the loop. Otherwise below while loop will not have a exit

        while (startpoint in startpoints):      # To avoid duplicating startpoints
            startpoint = random_candidates_fn()
        
        # To store boolean value with startpoint key to avoid reusing startpoints. I used boolean value here to lower the memory
        startpoints[startpoint] = True          
        

        current = startpoint

        for j in range(0, k):
            # do one iteration
            hv = pwhash_fn(current)
            next = reduce_fn(j, hv)
            current = next

        pc.inc(k) # increment by k

        if i > 0 and (pc.get() % 100000) < k:
            sys.stdout.write('.')
            sys.stdout.flush()

        endpoint = current

        if endpoint not in table:
            table[endpoint] = []
        table[endpoint].append({'chain': i, 'start': startpoint, 'end': endpoint})

    utils.write_json(out_fp, table)
    print(' done.')


## TODO: Problem 2.1 --- (20 pts) ##
"""
## Rainbow table lookup.

    Inputs:
        pc: performance counter (PerfCounter),
        in_fp: table filepath,
        k: length of each chain,
        pwhash_fn: compute password hash function,
        reduce_fn: reduce function family,
        pwhash_list: the list of password hashes we want to invert (find the plaintext password for)
        
    Outputs:
        results: array of length len(pwhash_list) containing the matching passwords (or None)
"""
def lookup_rainbow(pc, in_fp, k, pwhash_fn, reduce_fn, pwhash_list, verbose = False):

    table = utils.read_json(in_fp)

    pwres = [None for i in range(len(pwhash_list))]
    for pwidx, pwhash in enumerate(pwhash_list):

        chain_infos = []
        ## TODO ##
        ## Put your code here
        for i in range(0,k):        # To start reducing the hash value with all reduce functions (R_k's)
            pwhash_next = pwhash    # To initialize next hash value as the given hash value at each k iterations
            for l in range(i,k):    # To propagate through hash-reduce chain starting from R_i th function to R_k th
                reduce_next = reduce_fn(l, pwhash_next) # To get reduce value from R_l th reduce function
                pwhash_next = pwhash_fn(reduce_next)    # To get the hash value from obtained reduce
                if reduce_next in table.keys():         # To check reduce is a rainbow table endpoint or not
                    chain_infos += table[reduce_next]   # If reduce is a endpoint of rainbow table then add the chain to the list

        verbose = False            
        # raise NotImplementedError()

        pc.inc(k)  # increment by k

        for j, chain_info in enumerate(chain_infos):
            chain_idx = chain_info['chain']
            startpoint = chain_info['start']
            current = startpoint
            if pwres[pwidx] is not None:
                break

            found = False
            ## TODO ##
            ## Put your code here
            for j in range(0, k):               # To recreate the recognized chains from the rainbow table
                # do one iteration
                hv = pwhash_fn(current)
                next = reduce_fn(j, hv)
                if hv == pwhash:                # TO check calculated hash value is equal to password hash or not
                    found = True                # If match the we found the password
                    pwres[pwidx] = current      # To update the cracked password
                    break                       
                current = next                  
            else:
                verbose = True                  # If the hash is not in the created chain, then update this to get a false alarm 

            if verbose and not found:
                print('\t[False alarm] for pwhash {} in chain {} [start: {}, end: {}]!'.format(pwhash, chain_idx, startpoint, chain_info['end']))

    return pwres
