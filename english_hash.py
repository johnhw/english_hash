"""
Hash files using SHA512, and return the hash as a set of short English words.
The script can either hash entire files, or optionally hash a repeatable random subsample
of a file. This allows for very fast hashing of large files with adjustable probability
of collision. 

A list of 4096 short (mainly one and two syllable) common English word is used to encode
the hash in 12 bit blocks. The hash is padded out to 528 bits so 43 complete words
can be formed. 

The script can return any subset of the hash words (e.g. first four words). This makes
a good human memorable/vocalisable hash, for example for confirming file matches over the phone.

BSD 2 Clause License
Copyright (c) 2014, John Williamson
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import bz2, base64, sys, hashlib, math, os, argparse, random

# The word list, as a space separated string, bzip2'd and base64 encoded
compressed_wordlist = """
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
+b29DP4u5IpwoSHqsp5y"""

# decompress the string into a list of 4096 words
wordlist = bz2.decompress(base64.b64decode(compressed_wordlist)).split(" ")


def key_to_english(s, words):
    """Take a string of 8-bit characters s and a list of words.
    Encode the string by indexing into the wordlist, treating the string
    as a stream of bits from which indices can be formed. """
    # compute max number of bits this word list can encode (i.e. max index)
    nbits = int(math.floor(math.log(len(words))/math.log(2)))
    out = []
    ix = 0
    n = 0       
    for char in s:
        byte = ord(char)        
        while byte!=0:
            ix = ix << 1
            ix = ix | (byte&1)            
            byte = byte >> 1
            n = n + 1                    
            if n==nbits:
                out.append(words[ix])                
                n = 0
                ix = 0              
    # output trailing words
    if n>0:
        out.append(words[ix])
    return out


def sha_file(sha, f):    
    """Compute the SHA hash of the given file-like object, reading
    one 1Mb block at a time. Return the full hash, plus a secondary
    hash (computed by feeding the digest back in) to use as extra padding"""        
    read = None
    while read!='':
        read = f.read(1024*1024)
        sha.update(read)
        
    hash = sha.digest()
    sha.update(sha.digest())
    hash2 = sha.digest()
    return hash, hash2
    
    
def sha_file_random(sha, f, percent=None, n_blocks=None, min_blocks=100, max_blocks=None, block_size=512, filesize=None):
    """Compute a hash from a randomized set of blocks from a file. Percent specifies the percentage
    of the file to inspect (0.0-100.0); alternatively, n_blocks specifies the number of blocks
    to inspect. min_blocks and max_blocks limit the number of blocks inspected. The size
    of blocks is given by block (default 512).
    
    Note that this depends on the reproducibility of the Python PRNG. If this changes, hashes
    will not match.
    
    The file object must support seek(), and if filesize is not specified, must be a real file.    
    """
    if block_size is None:
        block_size = 512
        
    # check file size
    if filesize is None:
        size = os.fstat(f.fileno()).st_size
    else:
        size = filesize
        
    # compute number of blocks to inspect
    if n_blocks is None:        
        n_blocks = int(((size/block_size)*percent)/100)                
    if min_blocks is not None:
        n_blocks = max(n_blocks, min_blocks)    
    if max_blocks is not None:
        n_blocks = min(n_blocks, max_blocks)     
        
    # include first and last block always
    block_offsets = [0] + [random.randint(0,max(0,size-block_size)) for i in range(n_blocks)] + [size-block_size]
    
    # sort to minimise seek time
    block_offsets = sorted(block_offsets)        
        
    # use consistent seed
    sha.update(str(size))
    random.seed(sha.digest())
    
    for offset in block_offsets:           
        f.seek(offset)
        sha.update(f.read(block_size))
        
    hash = sha.digest()
    sha.update(sha.digest())
    hash2 = sha.digest()    
    return hash, hash2
    
def wordhash(sha, f, n=None, blocks=None, percent=None, **kwargs):    
    """Compute the hash of a file-like object, returning as a space-separated list of words.
    The encoded string includes one extra byte from a secondary hash, to avoid
    trailing low-order bits for 12-bit indices. """
    
    
    # use randomisation only if blocks or percent is specified
    if blocks is not None or percent is not None:
        hash, hash2 = sha_file_random(sha, f, percent=percent, n_blocks=blocks, **kwargs) 
    else:
        hash, hash2 = sha_file(sha, f)     
    word_bits = 12
    char_bits = 8
    padding = word_bits-((len(hash)*char_bits)%word_bits)
    padding_bytes = padding//char_bits
    words = key_to_english(hash+hash2[0:padding_bytes], wordlist)
    if n!=None:
        words = words[0:n]        
    return " ".join(words)


def wordhash_file(sha, fname, **kwargs):
    """Hash the file with the given path, returning the space-separated word form. 
    Just a wrapper for wordhash that opens the given file. """
    with open(fname, "rb") as f:
        return wordhash(sha, f, **kwargs)
        
if __name__=="__main__":
    parser = argparse.ArgumentParser(description='Print a readable, pronounceable SHA512 hash of a file. Optionally, read a (repeatable) randomised subset of the file for faster hashing.')
    parser.add_argument('files', metavar='<file>', type=str, nargs='*',
                   help='Files to be hashed.')
    parser.add_argument('-n','--nwords', dest='nwords', metavar='<n>', type=int,
                   help='Number of words per hash. n=43 is maximum; n=12 is default.')
    parser.add_argument('-p','--percent', dest='percent', metavar='<n>', type=float,
                   help='Percentage of file to inspect, as float [0.0, 100.0]. Forces randomisation, even if n=100. Only one of --percent and --blocks should be specified.')
    parser.add_argument('-b','--blocks', dest='blocks', metavar='<n>', type=int,
                   help='Number of blocks to inspect. Forces randomisation. Only one of --percent and --blocks should be specified.')
    parser.add_argument('-k','--block-size', dest='block_size', metavar='<n>', type=int,
                   help='Size of blocks in randomised mode. Default is 512 bytes.')
    
    parser.add_argument('--min-blocks', dest='min_blocks', metavar='<n>', type=int,
                   help='Minimum number of blocks to inspect in randomised mode. First and last block are always inspected.')
    parser.add_argument('--max-blocks', dest='max_blocks', metavar='<n>', type=int,
                   help='Maximum number of blocks to inspect in randomised mode. First and last block are always inspected.')                                                                                               
    args = parser.parse_args()
    
    n = args.nwords
    
    if n is None:
        n = 12        
        
    sha = hashlib.sha512()        
    if len(args.files)==0:
        # by default, hash this script
        thisfile = os.path.realpath(sys.argv[0])
        print "Hash of this script (%s):  %s"  % (sys.argv[0], wordhash_file(sha, thisfile, n=n, 
        percent=args.percent, blocks=args.blocks, block_size=args.block_size, min_blocks=args.min_blocks, max_blocks=args.max_blocks))
    else:
        # hash the given files
        for file in args.files:
            print wordhash_file(sha,file,n=n,percent=args.percent, blocks=args.blocks, block_size=args.block_size, min_blocks=args.min_blocks, max_blocks=args.max_blocks)
    

