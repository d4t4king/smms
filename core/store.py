import sys
from utils.smmssqlutils import smmssqlutils

class store():
    def __init__(self, outputxml, **kwargs):
        self.outputxml = outputxml
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
        import xmltodict
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        # sqlite3 and .data.db are defaults, so just use that.
        db = smmssqlutils(dbtype='sqlite3', dbfile='stores.db')
        #print(str(dir(db)))
        with open(outputfile, 'rb') as f:
            xdoc = xmltodict.parse(f, xml_attribs=True)
        for h in xdoc['nmaprun']['host']:
            pp.pprint(h['ports'])
            for p in h['ports']:
                pp.pprint(h['ports']['port'])
                pobj = h['ports']['port']
                print("{} - {}/{}".format(h['address']['@addr'], \
                    pobj['@protocol'], pobj['@portid']))
