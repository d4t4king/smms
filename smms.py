#!/usr/bin/env python3

import sys
from smms import scan
import argparse

def main():
    sys.dont_write_bytecode = True

    parser = argparse.ArgumentParser("Scan a target and keep track of stuff.")
    parser.add_argument('-t', '--target', dest='target', \
        help="The targets for the scan.")
    parser.add_argument('-p', '--port', type=int, dest='port', \
        help="The port to scan for.")
    parser.add_argument('action', help="What you want to accmpllish.")
    args = parser.parse_args()

    if args.action == 'scan':
        _scan = scan.scan(target=args.target, port=args.port)
        _scan.scan()
    else:
        if args.action is None:
            print("YOu must specify an action to run:")
            print("\tscan, store, archive, gather, vuln, stats, times")
            exit(0)
        else:
            print("Unrecognized action: {}".format(args.action))


if __name__=='__main__':
  main()
