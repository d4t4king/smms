import sys

class smmsutils():
    sys.dont_write_bytecode = True

    SERVICES = {}
    SERVICES['ftp'] = [21]
    SERVICES['http'] = [80,8000,8080]
    SERVICES['https'] = [443,8443]
    SERVICES['mssql'] = [1433]
    SERVICES['mysql'] = [3306]
    SERVICES['oracle'] = [1521]
    SERVICES['pclpjl'] = [9100]
    SERVICES['postgres'] = [5432]
    SERVICES['rdp'] = [3398]
    SERVICES['rsh'] = [514]
    SERVICES['smtp'] = [25]
    SERVICES['ssh'] = [22]
    SERVICES['telnet'] = [23]
    SERVICES['vnc'] = [5800,5900,5901,5902,5903,5904,5905,5906,5910]
    SERVICES['vpn'] = [1701,1723]

    def get_xml_addrlist(xmlfile, sort=False):
        import xml.etree.ElementTree as et
        tree = None
        try:
            tree = et.parse(xmlfile)
        except et.ParseError as err:
            if 'unclosed token' in str(err):
                print("Truncated XML file ({})".format(xmlfile), file=sys.stderr)
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

    def which(pgm):
        import os
        path = os.getenv('PATH')
        for p in path.split(os.path.pathsep):
            p = os.path.join(p, pgm)
            if os.path.exists(p) and os.access(p, os.X_OK):
                return p
