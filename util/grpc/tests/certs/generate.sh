openssl req -x509 -newkey rsa:4096 -keyout server1.key -out server1.crt -days 3650 -subj "/C=US/ST=Neverland/L=California/O=Company Name/OU=Org/CN=www.server1.com" -nodes

openssl req -x509 -newkey rsa:4096 -keyout server2.key -out server2.crt -days 3650 -subj "/C=US/ST=Neverland/L=California/O=Company Name/OU=Org/CN=www.server2.com" -nodes

