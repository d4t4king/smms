import logging

class SyslogBOMFormatter(logging.Formatter):
  def format(self, record):
    result = super().format(record)
    return "smms_scan" + record
    
