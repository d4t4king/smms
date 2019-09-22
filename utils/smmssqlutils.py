class smmssqlutils():
  def __init__(self, **kwargs):
    import re
    DBTYPES_RGX = re.compile(r'(?sqlite3|mysql|mssql|oracle|postgre), re.IGNORECASE)

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
    self.pass = None
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
            self.pass = kwargs['pass']
        if 'port' in kwargs.keys() and \
            kwargs['port'] is not None:
            self.port = kwargs['port']
        else:
            self.port = DEFAULT_PORTS[self.dbtype]

	def dbsetup(self):
		if 'sqlite3' in self.dbtype:
			import sqlite3
			tables = {}
			tables['found'] = ("CREATE TABLE IF NOT EXISTS found ",
						"(id integer primary key autoincrement, ",
						"service text, ",
						"ip_addr text, hostname text, ",
						"first_found integer, last_found integer, ",
						"banner text, title text, ",
						"service_status text);")
			tables['vulns'] = ("CREATE TABLE if NOT EXISTS vulns ",
						"(id integer primary key autoincrement, ",
						"service text, port_num integer, ",
						"proto text, host_id integer, ",
						"first_found integer, last_found integer, ",
						"current_found integer, ",
						"nmap_script_name text, ",
						"vuln_name text, notified integer, ",
						"fixed integer);")
			tables['times'] = ("CREATE TABLE IF NOT EXISTS times ",
						"(id integer primary key autoincrement, ",
						"datetime integer, script_name text, ",
						"script_args text, start_time integer, ",
						"end_time integer, diff integer, ",
						"avg_atom_time double);")
			tables['http_meta'] = ("CREATE TABLE IF NOT EXISTS http_meta ",
						"(id integer primary key autoincrement, ",
						"service text, ip_addr text, ",
						"server_header text, ",
						"header_first_found integer, ",
						"header_last_updated integer, ",
						"html_title text, title_first_found integer, ",
						"title_last_updated integer);")
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
