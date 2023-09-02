from socket import *

def Scan(Host,Port):
    try:
        conskt = socket(AF_INET, SOCK_STREAM)
        conskt.connect((Host,Port))
        print('[+]%d/tcp open'% Port)
        conskt.close()
    except:
        print('[-]%d/tcp closed'% Port)

def portScan(Host, Port):
    try:
        IP = gethostbyname(Host)
    except:
        print('[-] Connot resolve %s'% Host)
        return
    try:
        Name= gethostbyaddr(IP)
        print('\n[+] Scan result of: %s ' % Name[0])
    except:
        print('\n[+] Scan result of: %s ' % IP)
    setdefaulttimeout(1)
    for Port in Ports:
        print('Scanning Port: %d'% Port)
        Scan(Host, int(Port))


if __name__ == '__main__':
    Scan('8.8.8.8', [80])