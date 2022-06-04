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

def get_proto(proto):
        match proto:
                case 6:  # TCP
                    return 1
                case 17: # UDP
                    return 2
                case 1:  # ICMP
                    return 3
                case 58: # ICMP
                    return 3
                case _:  # OTHER
                    return 0