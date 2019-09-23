import logging

class SyslogBOMFormatter(logging.Formatter):
    sys.dont_write_bytecode = True
    def format(self, record):
        result = super().format(record)
        return "smms_scan" + record
