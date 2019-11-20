Privacy-preserving DPI over TLS encrypted traffic

based on tls 1.2

the repo of my implementation of mctls contains the original tlslite-ng source code

to add new message, need to add_dynamic_size in tlsrecordlayer.py
may need to call sock.flush()