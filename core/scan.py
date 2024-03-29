import sys
import datetime
from core.store import store
from utils.smmsutils import smmsutils as sm
from utils.smmssqlutils import smmssqlutils as db

class scan():
    sys.dont_write_bytecode = True

    def __init__(self, **kwargs):
        today = datetime.datetime.now()
        self.target = kwargs['target'] \
            if 'target' in kwargs.keys() else None
        self.port = kwargs['port'] \
            if 'port' in kwargs.keys() else 0
        self.ports = []
        self.service = kwargs['service'] \
            if 'service' in kwargs.keys() else None
        if self.service and not self.port:
            #print(dir(sm))
            self.ports = ",".join([str(x) for x in sm.SERVICES[kwargs['service']]])
        self.scan_output = None
        if 'outputfile' in kwargs.keys():
            self.scan_output = kwargs['outputfile']
        else:
            if self.port != 0:
                self.scan_output = "{dt}.xml".format( \
                    dt=today.strftime('%s'))
            else:
                self.scan_output = "{dt}.xml".format( \
                    dt=today.strftime('%s'))
        self.masscan = sm.which('masscan')
        if 'masscan_path' in kwargs.keys():
            self.masscan = kwargs['masscan_path']
        self.nmap = sm.which('nmap')
        if 'nmap_path' in kwargs.keys():
            self.nmap = kwargs['nmap_path']
	

    def scan(self):
        if not self.target:
            print("Can't scan a target of None.")
            exit(1)
        if self.masscan is None:
            print("You need to install masscan or provide a path with '-M|--masscan-path'.")
            exit(1)
        ms_cmd = self.masscan
        if self.port:
            ms_cmd += " -p {port} --max-rate 10000 -oX {fn} {tgt}".format( \
                port=self.port, fn=self.scan_output, tgt=self.target)
        elif self.service:
            ms_cmd += " -p {port} --max-rate 10000 -oX {fn} {tgt}".format( \
                port=self.ports, fn=self.scan_output, tgt=self.target)
        print("Scanning with the following command:")
        print(ms_cmd)
        import subprocess
        subprocess.call(ms_cmd.split(' '))
        print("Scan complete.")
        stor = store(dbtype='sqlite3', outputxml='stores.db')
        #print(dir(stor))
        stor.simple_store(self.scan_output)
