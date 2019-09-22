import sys
import sqlite3

class store():
    def __init__(self, outputfile, **kwargs):
        self.outputfile = outputfile
        if 'dbtype' not in kwargs.keys():
            raise Exception('Unable to determine dbtype!')
        self.dbtype = kwargs['dbtype']
        self.dbfile = None
        if 'sqlite3' in self.dbtype:
            if 'dbfile' not in kwargs.keys() or \
                kwargs['dbfile'] is None or \
                kwargs['dbfile']=='':
                print("No dbfile specified, using default.")
                self.dbfile = '.data.db'
        else:
            print("Don't know how to handle dbtype {} yet.".format(self.dbtype))

    def simple_store(self, outputfile):
        from utils.smmssqlutils import smmssqlutils
        # sqlite3 and .data.db are defaults, so just use that.
        db = smmssqlutils()
        print(str(dir(db)))
