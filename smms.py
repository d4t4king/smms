#!/usr/bin/env python3

import sys
from core.scan import scan
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

    # load config
    # core.load_config()
    # set up db if needed
    # sqlutils_obj = smmssqlutils.smmssqlutils(dbtype='sqlite3', dbfile=dbfile)
    if args.action == 'scan':
        scn = scan(target=args.target, port=args.port)
        scn.scan()
        # maybe these go in core with scan()
        # ... and are called by scan.scan()
        #store.simple_store()
        #archive.simple_archive()
    else:
        if args.action is None:
            print("YOu must specify an action to run:")
            print("\tscan, store, archive, gather, vuln, stats, times")
            exit(0)
        else:
            print("Unrecognized action: {}".format(args.action))


if __name__=='__main__':
  main()
