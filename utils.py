# -*- coding: utf-8 -*-
""" CNT5410 -- Assignment 1: Passwords -- utils.py
"""

import json
import re
import os
import time

## os / paths
def ensure_exists(dir_fp):
    if not os.path.exists(dir_fp):
        os.makedirs(dir_fp)

## json stuff

# write a dict or a json string to file
def write_json(fp, obj_or_str):
    json_obj = obj_or_str
    if isinstance(obj_or_str, str):
        json_obj = json.loads(obj_or_str)
        
    with open(fp, 'w') as f:
        json.dump(json_obj, f, sort_keys=True, indent=4, separators=(',', ': '))    
    
# read a json obj from file and return a dict
def read_json(fp):
    with open(fp, 'r') as f:
        obj = json.load(f)
    return obj


## word list
def get_words():
    with open('data/words.list', 'r') as f:
        words = f.readlines()
    words = [w.strip() for w in set(words)]
    words.sort()
    return words


## performance

class PerfCounter:
    def __init__(self):
        self.counter = 0
        self.startt = None
        self.stopt = None
        self.duration = None

    def inc(self, c=1):
        assert c >= 0
        self.counter += c

    def start(self):
        self.startt = time.time()

    def stop(self):
        assert self.startt is not None, "Timer not started!"
        self.stopt = time.time()
        self.duration = self.stopt - self.startt

    def get(self):
        return self.counter

    def perf(self):
        assert self.startt is not None, "Timer not started!"
        assert self.duration is not None, "Timer not stopped!"

        return self.counter, self.duration


    
## tests
    
# run test_fn and cleanup_fn no matter what
def test_with_cleanup(test_fn, cleanup_fn):
    try:
        test_fn()
    except AssertionError:
        raise 
    finally:
        cleanup_fn()
