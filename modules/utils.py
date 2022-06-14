import time

def get_avg(proto, data):
        res = {
            'proto': proto,
            'portmin': data['portmin'],
            'portmax': data['portmax'],
            'ports': data['ports']/data['count'],
            'delay': data['delay']/data['count'],
            'count': data['count'],
            'length': data['length']/data['count']
        }
        return res

def get_num_proto(proto):
    match proto:
            case 'TCP':   # TCP
                return 1
            case 'UDP':   # UDP
                return 2
            case 'ICMP':  # ICMP
                return 3
            case 'DATA':  # DATA
                return 4
            case _:       # OTHER
                return 0

def data_msg(ip, token, payload=None, name=None, type='Alert'):
    return {'type': type, 'ip': ip, 'payload':payload, 'tmstmp':time.time(), 'token':token}

