import socket as sk
import argparse
import concurrent.futures
import logging


def scan_port(ip_address, port):
    try:
        with sk.socket(sk.AF_INET, sk.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            # set the TCP flag to SYN
            tcp_flag_syn = 0x02
            # send a SYN packet and wait for a response
            result = sock.connect_ex((ip_address, port))
            # check the response
            if result == 0:
                # send a RST packet to close the connection
                sock.sendall(tcp_flag_syn.to_bytes(1, 'big'))
                logging.info(f" Port: {str(port)} -> OPEN")
    except sk.timeout:
        logging.debug(f"Timed out while scanning port {port} on {ip_address}")
    except sk.error as e:
        logging.debug(f"Error while scanning port {port} on {ip_address}: {e}")


def scan(target, ports):
    logging.info(f"Scanning target {target} for ports 1-{ports}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(1, ports + 1):
            executor.submit(scan_port, target, port)


def main():
    parser = argparse.ArgumentParser(description='TCP port scanner')
    parser.add_argument('targets', help='Target(s) to scan (comma-separated)')
    parser.add_argument('ports', type=int, help='Number of ports to scan')
    parser.add_argument('--log', dest='log_level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='Set the logging level')
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=args.log_level)

    targets = args.targets.split(",")
    ports = args.ports

    for target in targets:
        scan(target.strip(), ports)


if __name__ == "__main__":
    main()
