import sys
import datetime
from core.store import store
from utils import smmsutils as sm, smmssqlutils as smsql

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
            self.ports = sm.SERVICES[kwargs['service']]
        self.scan_output = None
        if 'outputfile' in kwargs.keys():
            self.scan_output = kwargs['outputfile']
        else:
            if self.port != 0:
                self.scan_output = "{p}_{tgt}_{dt}.xml".format( \
                    p=self.port, tgt=self.target.replace('/', '-'), \
                    dt=today.strftime('%s'))
            else:
                self.scan_output = "{p}_{tgt}_{dt}.xml".format( \
                    p=self.ports, tgt=self.target.replace('/', '-'), \
                    dt=today.strftime('%s'))

    def scan(self):
        if not self.target:
            print("Can't scan a target of None.")
            exit(1)
        masscan = sm.smmsutils.which('masscan')
        if masscan is None:
            print("You need to install masscan or provide a path with '-M|--masscan-path'.")
            exit(1)
        if self.port:
            masscan += " -p {port} --max-rate 10000 -oX {fn} {tgt}".format( \
                port=self.port, fn=self.scan_output, tgt=self.target)
        elif self.service:
            masscan += " -p {port} --max-rate 10000 -oX {fn} {tgt}".format( \
                port=self.ports, fn=self.scan_output, tgt=self.target)
        print("Scanning with the following command:")
        print(masscan)
        import subprocess
        subprocess.call(masscan.split(' '))
        print("Scan complete.")
