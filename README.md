# dnsResponse
dns response view

To compile please do the following:
gcc -o dnsRspApp samHomeAssignment.c -lpcap

To run the application:
sudo ./dnsRspApp

I have used a windows machine with WSL were ive installed this ubuntu version "Ubuntu 24.04.2 LTS". 
Those are the commands ive tried to test my application with. 

nslookup google.com
nslookup youtube.com
nslookup facebook.com
nslookup amazon.com
nslookup apple.com
nslookup microsoft.com
nslookup netflix.com
nslookup cloudflare.com
nslookup openai.com
nslookup cnn.com 

nslookup -type=CNAME www.youtube.com
nslookup -type=CNAME www.apple.com


i created also a python script to simulate ipv6 dns as i dont have ipv6 machine. 
once the dns application is up run the below:
sudo python3 send_ipv6_dns.py
