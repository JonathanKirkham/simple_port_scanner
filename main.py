import socket as sk


def main():
    targets = input("[*] Enter Target to Scan -> (Split by using ,): ")
    ports = int(input("[*] Enter how many ports you want scan: "))

    def scan(target, ports):
        print(f" \n Starting scan for {str(target)}")
        for port in range(1, ports):
            scan_port(target, port)

    def scan_port(ip_address, port):
        try:
            sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            sock.settimeout(.25)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                print(f"[+] Port: {str(port)} -> OPEN")
        except:
            pass

    if "," in targets:
        print("[*] Scanning multiple targets")
        for ip_addr in targets.split(","):
            scan(ip_addr.strip("  "), ports)
    else:
        scan(targets, ports)


if __name__ == "__main__":
    main()
