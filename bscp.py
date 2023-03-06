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

import pyximport; pyximport.install()
import typer
import hashlib
import struct
import subprocess
import sys
import pickle
import time
from pprint import pprint
from rich.progress import Progress


main = typer.Typer()

if sys.version_info < (3, 0):
    range = xrange

remote_script = r'''
import hashlib
import os
import os.path
import struct
import sys

if sys.version_info < (3, 0):
    stdin_buffer = sys.stdin
    stdout_buffer = sys.stdout
    range = xrange
else:
    stdin_buffer = sys.stdin.buffer
    stdout_buffer = sys.stdout.buffer

(size, blocksize, filename_len, hashname_len, skip_digest, skip_final_digest) = struct.unpack('<QQQQ??', stdin_buffer.read(8+8+8+8+1+1))
filename_bytes = stdin_buffer.read(filename_len)
hashname_bytes = stdin_buffer.read(hashname_len)
filename = filename_bytes.decode('utf-8')
hashname = hashname_bytes.decode('ascii')

sanity_hash = hashlib.new(hashname, filename_bytes).digest()
stdout_buffer.write(sanity_hash)
stdout_buffer.flush()
if stdin_buffer.read(2) != b'go':
    sys.exit()

if not os.path.exists(filename):
    # Create sparse file
    with open(filename, 'wb') as f:
        f.truncate(size)
    os.chmod(filename, 0o600)

with open(filename, 'rb+') as f:
    f.seek(0, 2)
    stdout_buffer.write(struct.pack('<Q', f.tell()))
    readremain = size
    rblocksize = blocksize
    f.seek(0)
    if skip_digest is False:
        while True:
            if readremain <= blocksize:
                rblocksize = readremain
            block = f.read(rblocksize)
            if len(block) == 0:
                break
            digest = hashlib.new(hashname, block).digest()
            stdout_buffer.write(digest)
            readremain -= rblocksize
            if readremain == 0:
                break
    stdout_buffer.flush()
    while True:
        position_s = stdin_buffer.read(8)
        if len(position_s) == 0:
            break
        (position,) = struct.unpack('<Q', position_s)
        block = stdin_buffer.read(blocksize)
        f.seek(position)
        f.write(block)
    if skip_final_digest is True:
        exit(0)
    readremain = size
    rblocksize = blocksize
    hash_total = hashlib.new(hashname)
    f.seek(0)
    while True:
        if readremain <= blocksize:
            rblocksize = readremain
        block = f.read(rblocksize)
        if len(block) == 0:
            break
        hash_total.update(block)
        readremain -= rblocksize
        if readremain == 0:
            break
stdout_buffer.write(hash_total.digest())
'''

class IOCounter:
    def __init__(self, in_stream, out_stream):
        self.in_stream = in_stream
        self.out_stream = out_stream
        self.in_total = 0
        self.out_total = 0
    def read(self, size=None):
        if size is None:
            s = self.in_stream.read()
        else:
            s = self.in_stream.read(size)
        self.in_total += len(s)
        return s
    def write(self, s):
        self.out_stream.write(s)
        self.out_total += len(s)
        self.out_stream.flush()


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


def digest_load(filename):
    digest = None
    try:
        with open(filename+".v2", "rb") as infile:
            my_dict = pickle.loads(infile.read())
            return (my_dict['digest'], my_dict['position'], my_dict['idx'])
    except FileNotFoundError:
        pass
    try:
        with open(filename, "rb") as infile:
            digest = pickle.loads(infile.read())
    except FileNotFoundError:
        pass
    return (digest, 0, 0)


def bscp(local_filename,
         remote_host,
         remote_filename,
         blocksize,
         hashname,
         skip_remote_digest=False,
         skip_remote_final_digest=False,
         debug=False,
         digest_save_name=None,
         digest_interval_save=600,
         update_progress_interval=30,
         config_map={},
    ):
    remote_filename_bytes = remote_filename.encode('utf-8')
    hashname_bytes = hashname.encode('ascii')
    hash_total = hashlib.new(hashname)
    zero_remote_digest=skip_remote_digest
    with open(local_filename, 'rb') as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(0)
        start_position=0
        start_idx=0

        # Calculate number of blocks, including the last block which may be smaller
        blockcount = int((size + blocksize - 1) / blocksize)
        if digest_save_name is not None and skip_remote_digest is False:
            (remote_digest_list, start_position, start_idx) = digest_load(digest_save_name)
            if remote_digest_list is not None:
                skip_remote_digest = True
        f.seek(start_position)

        remote_command = 'python -c "%s"' % (remote_script,)
        if remote_host == 'local':
           command = ('sh','-c',remote_command)
        else:
           command = ('ssh', '--', remote_host, remote_command)

        if config_map.get("remote_info_only", False) is True:
            print(f"python ./bscp_remote_only.py '{remote_filename}' '{hashname}' {size} {blocksize} <output_filename>")
            exit(0)

        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
        io = IOCounter(p.stdout, p.stdin)

        send_size = size
        send_blockcount = blockcount
        io.write(struct.pack('<QQQQ??', send_size, blocksize, len(remote_filename_bytes), len(hashname_bytes), skip_remote_digest, skip_remote_final_digest))
        io.write(remote_filename_bytes)
        io.write(hashname_bytes)

        sanity_digest = hashlib.new(hashname, remote_filename_bytes).digest()
        remote_digest = io.read(len(sanity_digest))
        if remote_digest != sanity_digest:
            raise RuntimeError('Remote script failed to execute properly')
        io.write(b'go')

        (remote_size,) = struct.unpack('<Q', io.read(8))
        if remote_size < size:
            raise RuntimeError('Remote size less than local (local: %i, remote: %i)' % (size, remote_size))
        sys.stderr.write('getting remote digest.\n')
        #remote_digest_list = [io.read(hash_total.digest_size) for i in range(blockcount)]
        if skip_remote_digest is False:
            with typer.progressbar(range(send_blockcount)) as progress:
                remote_digest_list = [io.read(hash_total.digest_size) for i in progress]
            sys.stderr.write('ready remote digest.\n')


        if debug is True:
            pprint(remote_digest_list)

        pos_location=0
        if zero_remote_digest is True:
            remote_digest_list = [None] * blockcount

        if digest_save_name is not None:
            digest_save(digest_save_name, remote_digest_list)
            next_save_time = int(time.time()) + digest_interval_save
        else:
            next_save_time = None
        changed = False

        next_progress_time = int(time.time())
        blocks_written = 0
        blocks_skipped = 0
        if start_position > 0:
            print(f"starting from position: {start_position} / index: {start_idx} from {len(remote_digest_list)}")
            if skip_remote_final_digest is False:
                skip_remote_final_digest = True
                print("skipping remote final digest, because not starting from position 0")
        with Progress() as progress:
            task1 = progress.add_task("[cyan]Total...", total=len(remote_digest_list))
            task2 = progress.add_task("[green]Written...", total=len(remote_digest_list))
            task3 = progress.add_task("[yellow]Skipped...", total=len(remote_digest_list))

            for idx, remote_digest in enumerate(remote_digest_list):
                if idx < start_idx:
                    blocks_skipped += 1
                    continue
                position = f.tell()
                pos_location=pos_location+1

                block = f.read(blocksize)
                hash_total.update(block)
                digest = hashlib.new(hashname, block).digest()
                if digest != remote_digest:
                    blocks_written += 1
                    try:
                        io.write(struct.pack('<Q', position))
                        io.write(block)
                    except IOError:
                        break
                    remote_digest_list[idx] = digest
                    changed = True
                else:
                    blocks_skipped += 1
                if next_progress_time < int(time.time()):
                    next_progress_time = int(time.time()) + update_progress_interval
                    progress.update(task1, advance=(blocks_written + blocks_skipped))
                    progress.update(task2, advance=blocks_written)
                    progress.update(task3, advance=blocks_skipped)
                    progress.console.print(f"skipped {blocks_skipped}, written {blocks_written}.")
                    blocks_written = 0
                    blocks_skipped = 0

                #if changed is True and next_save_time is not None and int(time.time()) > next_save_time:
                if next_save_time is not None and int(time.time()) > next_save_time:
                    progress.console.print(f"saving digest to disk: {time.strftime('%H:%M:%S', time.localtime())}")
                    digest_save(digest_save_name, remote_digest_list, position=position, idx=idx)
                    next_save_time = time.time() + digest_interval_save
                    changed = False

            progress.update(task1, advance=(blocks_written + blocks_skipped))
            progress.update(task2, advance=blocks_written)
            progress.update(task3, advance=blocks_skipped)
        p.stdin.close()
        if digest_save_name is not None:
            digest_save(digest_save_name, remote_digest_list)

        if skip_remote_final_digest is False:
            remote_digest_total = io.read()
            p.wait()
            if remote_digest_total != hash_total.digest():
                raise RuntimeError('Checksum mismatch after transfer')
    return (io.in_total, io.out_total, size)

@main.command()
def bscp_main(
    local_filename,
    remote,
    blocksize: int = typer.Option(65536),
    hashname: str = typer.Option('sha256'),
    digest_save_name: str = typer.Option(None),
    digest_interval_save: int = typer.Option(200, help="Save digest every X seconds to disk"),
    update_progress_interval: int = typer.Option(30, help="Update progress interval every X seconds"),
    skip_remote_digest: bool = typer.Option(False, "--skip-remote-digest", "-s", help="Skip remote digest initial scan, copy all block's to start with"),
    skip_remote_final_digest: bool = typer.Option(False, "--skip-remote-final-digest", "-f", help="Skip remote digest initial scan, copy all block's to start with"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Debug mode"),
    remote_info_only: bool = typer.Option(False, "--remote-info-only", help="Get info for remote seperate run for digest."),
):
    try:
        (remote_host, remote_filename) = remote.split(":")
    except ValueError:
        print("remote needs to be:   <hostname>:<blockdevice>")
        print("or                :   local:<blockdevice>")
        sys.exit(1)

    config_map = dict()
    config_map['remote_info_only'] = remote_info_only

    (in_total, out_total, size) = bscp(
        local_filename,
        remote_host,
        remote_filename,
        blocksize,
        hashname,
        debug=debug,
        skip_remote_digest=skip_remote_digest,
        skip_remote_final_digest=skip_remote_final_digest,
        digest_save_name=digest_save_name,
        digest_interval_save=digest_interval_save,
        update_progress_interval=update_progress_interval,
        config_map=config_map,
    )
    speedup = size * 1.0 / (in_total + out_total)
    sys.stderr.write('in=%i out=%i size=%i speedup=%.2f\n' % (in_total, out_total, size, speedup))


if __name__ == "__main__":
    main()
