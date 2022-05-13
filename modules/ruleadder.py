from pyptables import default_tables, restore
from pyptables.rules import Drop, Accept

def block_ips(ips):
    tables = default_tables()
    for ip in ips:
        tables['filter']['INPUT'].append(Drop(source=ip))
    restore(tables)

def accept_ips(ips):
    tables = default_tables()
    for ip in ips:
        tables['filter']['INPUT'].append(Accept(source=ip))
    restore(tables)

if __name__ == "__main__":
    ips = [
        '1.1.2.2/32',
        '1.1.2.3/32',
        '1.1.2.4/32'
    ]
    accept_ips(ips)