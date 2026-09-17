import ipaddress

def validate_candidate(lines):
    errors=[]
    for number,line in enumerate(lines,1):
        if not line.startswith(("set vsys ","set device-group ","set network virtual-router ")): errors.append(f"Line {number}: unrecognized context")
        if " ip-netmask " in line:
            try: ipaddress.ip_network(line.rsplit(" ",1)[1],strict=False)
            except ValueError: errors.append(f"Line {number}: invalid network")
        if " protocol " in line and " port " in line:
            port=line.rsplit(" ",1)[1]
            if not all(x.isdigit() and 0<=int(x)<=65535 for x in port.split("-")): errors.append(f"Line {number}: invalid port")
    return errors