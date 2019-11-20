import socket
from tlslite import TLSConnection
from tlslite.api import *
from tlslite.utils.cryptomath import *
import sys
import ipaddress
import time
import random
import os

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'usage: ' + sys.argv[0] + ' server_ip server_port'
    else:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        cipher_suite = 'aes256gcm'
        curve_name = 'x25519'

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, server_port))
        
        # now use sock to establish TLS 1.3 connection with the remote server
        connection = TLSConnection(sock)
        settings = HandshakeSettings()
        settings.cipherNames = [cipher_suite]
        settings.eccCurves = list([curve_name])
        settings.defaultCurve = curve_name
        settings.keyShares = [curve_name]

        settings.maxVersion = (3, 3) # tls 1.2
        settings.versions = [(3, 3)]
        #settings.number_of_middleboxes = number_of_middleboxes
        settings.print_debug_info = True

        cert_file = "tests/serverX509Cert.pem"
        s = open(cert_file, "rb").read()
        if sys.version_info[0] >= 3:
            s = str(s, 'utf-8')
        x509 = X509()
        x509.parse(s)
        cert_chain = X509CertChain([x509])
        middlebox_public_key = cert_chain.getEndEntityPublicKey()
        settings.middlebox_public_key = middlebox_public_key
        connection.middlebox_public_key = middlebox_public_key
        #connection.number_of_middleboxes = number_of_middleboxes

        connection.handshakeClientCert(settings=settings)

        amout = 1024 * 1024 * 5
        count = 0
        time1 = time.time()
        while count < amout:
        	data = connection.recv(4096)
        	count += len(data)
        time2 = time.time()
        result = 5 / (time2 - time1)
        print 'throughput is ' + str(result) + ' MB/s'
        connection.close()