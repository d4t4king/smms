import sys

class smmssqlutils():
    sys.dont_write_bytecode = True
    
    def __init__(self, **kwargs):
        import re
        DBTYPES_RGX = re.compile(r'(?:sqlite3|mysql|mssql|oracle|postgre)', re.IGNORECASE)

        DEFAULT_PORTS = {}
        DEFAULT_PORTS['mssql'] = 1433
        DEFAULT_PORTS['mysql'] = 3306
        DEFAULT_PORTS['oracle'] = 1521
        DEFAULT_PORTS['postgre'] = 5432

        self.dbtype = None
        self.dbfile = None
        self.host = None
        self.database = None
        self.user = None
        self.passw = None
        self.port = 0

        if kwargs['dbtype'] is not None:
            self.dbtype = kwargs['dbtype']
        else:
            # default to sqlite3
            self.dbtype = 'sqlite3'

        if DBTYPES_RGX.search(self.dbtype) is None:
            raise ValueError("Unexpected database type: {}".format(self.dbtype))

        if 'sqlite3' in self.dbtype:
            if kwargs['dbfile'] is not None:
                assert isinstance(kwargs['dbfile'], str), \
                    "'dnfile' must be s tring.  Got {}".format(\
                        type(kwargs['dbfile']))
                self.dbfile = kwargs['dbfile']
            else:
                raise Exception("You must specify a dbfile with the 'sqlite3' dbtype.")
        else:
            if 'host' in kwargs.keys() and \
                kwargs['host'] is not None:
                self.host = kwargs['host']
            if 'database' in kwargs.keys() and \
                kwargs['database'] is not None:
                self.database = kwargs['database']
            if 'user' in kwargs.keys() and \
                kwargs['user'] is not None:
                self.user = kwargs['user']
            if 'pass' in kwargs.keys() and \
                kwargs['pass'] is not None:
                self.passw = kwargs['pass']
            if 'port' in kwargs.keys() and \
                kwargs['port'] is not None:
                self.port = kwargs['port']
            else:
                self.port = DEFAULT_PORTS[self.dbtype]

    def dbsetup(self):
        if 'sqlite3' in self.dbtype:
            import sqlite3
            tables = {}
            tables['config'] = ("CREATE TABLE IF NOT EXISTS config ",
                            "(name TEXT, value TEXT);")
            tables['hosts'] = ("CREATE TABLE IF NOT EXISTS hosts ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "hostname TEXT NOT NULL, ",
                            "ipv4addr TEXT NOT NULL);")
            tables['services'] = ("CREATE TABLE IF NOT EXISTS services ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "name TEXT, ports TEXT);")
            tables['found'] = ("CREATE TABLE IF NOT EXISTS found ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "host_id INTEGER NOT NULL, ",
                            "service_id INTEGER NOT NULL, ",
                            "first_found INTEGER, last_found INTEGER, ",
                            "scan_count INTEGER NOT NULL);")
            tables['vulns'] = ("CREATE TABLE IF NOT EXISTS vulns ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "name TEXT NOT NULL);")
            tables['vulns_found'] = ("CREATE TABLE IF NOT EXISTS vulns_found ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "host_id INTEGER NOT NULL, ",
                            "service_id INTEGER NOT NULL, ",
                            "vuln_id INTEGER NOT NULL, ",
                            "first_found INTEGER NOT NULL, ",
                            "last_found INTEGER NOT NULL);")
            tables['times'] = ("CREATE TABLE IF NOT EXISTS times ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "datetime INTEGER, script_name TEXT, ",
                            "script_args TEXT, start_time INTEGER, ",
                            "end_time INTEGER, diff INTEGER, ",
                            "avg_atom_time DOUBLE);")
            tables['http_meta'] = ("CREATE TABLE IF NOT EXISTS http_meta ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "service TEXT, ip_addr TEXT, ",
                            "server_header TEXT, ",
                            "header_first_found INTEGER, ",
                            "header_last_updated INTEGER, ",
                            "html_title TEXT, title_first_found INTEGER, ",
                            "title_last_updated INTEGER);")
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            for k,v in tables.items():
                #print("{}".format("".join(v)))
                c.execute("".join(v))
            conn.commit()
            conn.close()

    def _record_exists(self, table, field, value):
        print("|{}|".format(value))
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            # parameterized queries allows the SQL driver to translate
            # None to NULL.  (Even tho it should never be None.)
            sql = "SELECT id FROM {tn} WHERE {fn}=?".\
            format(tn=table, fn=field)
            try:
                c.execute(sql, (value,))
            except sqlite3.OperationalError as err:
                if 'table not found' in err.message:
                    print("You need to run dbsetup() prior to checking if a record exists.")
                    exit(1)
                else:
                    raise err
            result = c.fetchone()
            if result:
                print(result)
                return True
            else:
                return False
            conn.close()

    def host_exists(self, ipaddr):
        return self._record_exists('found', 'ip_addr', ipaddr)

    def get_host_id(self, host):
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            c.execute("SELECT id FROM found WHERE ip_addr=? OR hostname=?", \
            (host,host))
            res = c.fetchone()
            print("|{}|".format(res))
            conn.close()
        else:
            raise Exception("Don't know how to handle db type: {}".format(self.dbtype))
        if res:
            return int(res[0])
        else:
            return None

    def _insert_record(self, table, fields):
        assert isinstance(fields, dict), \
            "The fields parameter should be a dict of field/value pairs to insert."
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            sql = "INSERT INTO {tn} ( ".format(tn=table)
            sql += ",".join(fields.keys())
            sql += " ) VALUES ( '"
            sql += "','".join(fields.values())
            sql += "' );"
            #print(sql)
            c.execute(sql)
            conn.commit()
            conn.close()
        else:
            raise Exception("Don't know how to handle db type: {}".format(self.dbtype))

    def add_host(self, host_dict):
        self._insert_record('found', host_dict)
