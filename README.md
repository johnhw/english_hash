english_hash
============

A Python script which outputs SHA512 hashes as short English words.

Hash files using SHA512, and return the hash as a set of short English words.
The script can either hash entire files, or optionally hash a repeatable random subsample
of a file. This allows for very fast hashing of large files with adjustable probability
of collision. 

A list of 4096 short (mainly one and two syllable) common English word is used to encode
the hash in 12 bit blocks. The hash is padded out to 528 bits so 43 complete words
can be formed. 

The script can return any subset of the hash words (e.g. first four words). This makes
a good human memorable/vocalisable hash, for example for confirming file matches over the phone.

Usage
=====

    usage: englishash.py [-h] [-n <n>] [-p <n>] [-b <n>] [-k <n>]
                         [--min-blocks <n>] [--max-blocks <n>]
                         [<file> [<file> ...]]

    Print a readable, pronounceable SHA512 hash of a file. Optionally, read a
    (repeatable) randomised subset of the file for faster hashing.

    positional arguments:
      <file>                Files to be hashed.

    optional arguments:
      -h, --help            show this help message and exit
      -n <n>, --nwords <n>  Number of words per hash. n=43 is maximum; n=12 is
                            default.
      -p <n>, --percent <n>
                            Percentage of file to inspect, as float [0.0, 100.0].
                            Forces randomisation, even if n=100. Only one of
                            --percent and --blocks should be specified.
      -b <n>, --blocks <n>  Number of blocks to inspect. Forces randomisation.
                            Only one of --percent and --blocks should be
                            specified.
      -k <n>, --block-size <n>
                            Size of blocks in randomised mode. Default is 512
                            bytes.
      --min-blocks <n>      Minimum number of blocks to inspect in randomised
                            mode. First and last block are always inspected.
      --max-blocks <n>      Maximum number of blocks to inspect in randomised
                            mode. First and last block are always inspected.

License
=======

BSD 2 Clause License
Copyright (c) 2014, John Williamson
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                            