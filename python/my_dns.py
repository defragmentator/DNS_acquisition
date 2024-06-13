import socket

def getIP(d):
    """
    This method returns the first IP address string
    that responds as the given domain name
    """
    try:
        data = socket.gethostbyname(d)
        ip = repr(data)
        return ip
    except Exception as e:
        # fail gracefully!
        print(e)
        return False

print(getIP("2.75.250.142.b.barracudacentral.org"))
print(getIP("2.0.0.127.b.barracudacentral.org"))
