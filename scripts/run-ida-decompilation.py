#!/usr/bin/env python3

"""The script decompiles the given file via RetDec IDA plugin.
The supported decompilation modes are:
   full      - decompile entire input file.
   selective - decompile only the function selected by the given address.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys


script_full = 'retdec-decompile-full.idc'
script_selective = 'retdec-decompile-selective.idc'

TIMEOUT_RC = 137


def is_windows():
    return sys.platform in ('win32', 'msys') or os.name == 'nt'


def print_error_and_die(*msg):
    print('Error:', *msg)
    sys.exit(1)


def parse_args(args):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('file',
                        metavar='FILE',
                        help='The input file.')

    parser.add_argument('-o', '--output',
                        dest='output',
                        metavar='FILE',
                        help='Output file (default: file.c). All but the last component must exist.')

    parser.add_argument('-i', '--ida',
                        dest='ida_dir',
                        default=os.environ.get('IDA_DIR'),
                        help='Path to the IDA directory.')

    parser.add_argument('-d', '--idb',
                        dest='idb_path',
                        metavar='FILE',
                        help='IDA DB file associated with input file.')

    parser.add_argument('-s', '--select',
                        dest='selected_addr',
                        help='Decompile only the function selected by the given address (any address inside function). Examples: 0x1000, 4096.')

    parser.add_argument('--ea64',
                        dest='ea64',
                        action='store_true',
                        help='Use 64-bit address space plugin, i.e. retdec64 library and idat64 executable.')

    return parser.parse_args(args)


def check_args(args):
    if args.ida_dir is None:
        print_error_and_die('Path to IDA directory was not specified.')
    if not os.path.isdir(args.ida_dir):
        print_error_and_die('Specified path to IDA directory is not a directory:', args.ida_dir)

    if args.ea64:
        args.idat_path = os.path.join(args.ida_dir, 'idat64.exe' if is_windows() else 'idat64')
    else:
        args.idat_path = os.path.join(args.ida_dir, 'idat.exe' if is_windows() else 'idat')

    if not os.path.exists(args.idat_path):
        print_error_and_die('IDA console application does not exist:', args.idat_path)

    if args.idb_path and not os.path.exists(args.idb_path):
        print_error_and_die('Specified IDB file does not exist:', args.idb_path)

    if not args.file or not os.path.exists(args.file):
        print_error_and_die('Specified input file does not exist:', args.file)
    args.file_dir = os.path.dirname(args.file)

    if not args.output:
        args.output = args.file + '.c'

    args.output_dir = os.path.dirname(args.output)
    if not os.path.exists(args.output_dir):
        print_error_and_die('Output directory does not exist:', args.output_dir)


def main():
    args = parse_args(sys.argv[1:])
    check_args(args)

    if args.file_dir != args.output_dir:
        shutil.copy(args.file, args.output_dir)
        args.file = os.path.join(args.output_dir, os.path.basename(args.file))
        ida_in = args.file
    if args.idb_path and os.path.dirname(args.idb_path) != args.output_dir:
        shutil.copy(args.idb_path, args.output_dir)
        args.idb_path = os.path.join(args.output_dir, os.path.basename(args.idb_path))
        ida_in = args.idb_path

    rc = 0
    cmd = [args.idat_path, '-A']

    # Select mode.
    if args.selected_addr:
        cmd.append('-S' + script_selective + ' "' + args.file + '" ' + args.selected_addr)
    # Full mode.
    else:
        cmd.append('-S' + script_full + ' "' + args.file + '"')

    #cmd.append(args.file)
    cmd.append(ida_in)

    print('RUN: ' + ' '.join(cmd))
    rc = subprocess.call(cmd)

    # Plugin produces "<input>.c" -> copy the file to the desired output.
    out = args.file + '.c'
    if os.path.exists(out) and out != args.output:
        shutil.copyfile(out, args.output)

    return rc


if __name__ == "__main__":
    main()
