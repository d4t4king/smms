#!/usr/bin/env python3

import sys

def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


class SMMSUtils():
	SERVICES = {}
	SERVICES['ftp'] = [21]
	SERVICES['http'] = [80,8000,8080]
	SERVICES['https'] = [443,8443,]
	SERVICES['mssql'] = [1433]
	SERVICES['mysql'] = [3306]
	SERVICES['oracle'] = [1521]
	SERVICES['pclpjl'] = [9001]
	SERVICES['postgre'] = [5432]
	SERVICES['rdp'] = [3398]
	SERVICES['rsh'] = [514]
	SERVICES['smtp'] = [25,965]
	SERVICES['ssh'] = [22]
	SERVICES['telnet'] = [23]
	SERVICES['vnc'] = [5800,5900,5901,5902,5903,5904,5905,5906,5907,5908,5909,5910]
	SERVICES['vpn'] = [1701,1723]

	@staticmethod
	def get_xml_addrlist(xmlfile, sort=False):
		import xml.etree.ElementTree as et
		tree = None
		try:
			tree = et.parse(xmlfile)
		except et.ParseError as err:
			if 'unclosed token' in str(err):
				eprint("Truncated XML file ({})".format(xmlfile))
				return None
			else:
				raise err

		root = tree.getroot()
		addrs = []
		for a in root.iter('address'):
			addr = a.get('addr')
			if addr not in addrs:
				addrs.append(addr)
		if sort:
			addrs = sorted(addrs, key=lambda ip: \
									(int(ip.split('.')[0]),
									int(ip.split('.')[1]),
									int(ip.split('.')[2]),
									int(ip.split('.')[3])))
		return addrs	
		
class SMMSSQLUtils():

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
		self.server = None
		self.database = None
		self.user = None
		self.passw = None
		self.port = None


		if kwargs['dbtype'] is not None:
			self.dbtype = kwargs['dbtype']
		else:
			# default to sqlite3
			self.dbtype = 'sqlite3'

		if DBTYPES_RGX.search(self.dbtype) is None:
			# got an unknown type
			raise ValueError("Unexpected database type: ({})".format(self.dbtype))

		if 'sqlite3' in self.dbtype:
			if kwargs['dbfile'] is not None:
				assert isinstance(kwargs['dbfile'], str), \
					"'dbfile' must be a string.  Got {}".format(type(kwargs['dbfile']))
				self.dbfile = kwargs['dbfile']
		else:
			if 'server' in kwargs.keys() and \
				kwargs['server'] is not None:
				self.server = kwargs['server']
			else:
				self.server = None
			if 'database' in kwargs.keys() and \
				kwargs['database'] is not None:
				self.database = kwargs['database']
			else:
				self.database = None
			if 'user' in kwargs.keys() and \
				kwargs['user'] is not None:
				self.user = kwargs['user']
			else:
				self.user = None
			if 'pass' in kwargs.keys() and \
				kwargs['pass'] is not None:
				self.passw = kwargs['pass']
			else:
				self.passw = None
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
