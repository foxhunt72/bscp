#!/usr/bin/env python

# Copyright (C) 2012-2023  The Bscp Authors <https://github.com/bscp-tool/bscp/graphs/contributors>
# Changed from original by rdevos72@gmail.com
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import pickle
import time
import hashlib
import os
import os.path
import struct
import sys


def digest_save(filename, digest, position=0, idx=0):
    my_dict = {
        'digest': digest,
        'position': position,
        'idx': idx,
    }
    with open(filename, "wb") as outfile:
        pickle.dump(digest, outfile)
    with open(filename+".v2", "wb") as outfile:
        pickle.dump(my_dict, outfile)

def bscp_remote_only(filename, hashname, size, blocksize, output_filename):
    if not os.path.exists(filename):
        # Create sparse file
        with open(filename, 'wb') as f:
            f.truncate(size)
        os.chmod(filename, 0o600)

    remote_digest_list = list()
    with open(filename, 'rb+') as f:
        f.seek(0, 2)
        readremain = size
        rblocksize = blocksize
        f.seek(0)
        while True:
            if readremain <= blocksize:
                rblocksize = readremain
            block = f.read(rblocksize)
            if len(block) == 0:
                break
            digest = hashlib.new(hashname, block).digest()
            remote_digest_list.append(digest)
            readremain -= rblocksize
            if readremain == 0:
    digest_save(output_filename, remote_digest_list)

if __name__ == '__main__':
    try:
        filename = sys.argv[1]
        hashname = sys.argv[2]
        size = int(sys.argv[3])
        blocksize = int(sys.argv[4])
        output_filename = sys.argv[5]
    except:
        usage = 'bscp_remote_only.py <filename> <hashname> size blocksize <output_filename>'
        sys.stderr.write('Usage:\n\n    %s\n\n' % (usage,))
        sys.exit(1)
    bscp_remote_only(filename, hashname, size, blocksize, output_filename)
