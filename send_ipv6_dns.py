from scapy.all import Ether, IPv6, UDP, DNS, DNSQR, DNSRR, sendp

def send_fake_ipv6_dns():
    # create a fake DNS response with an AAAA record (IPv6)
    dns_resp = Ether()/IPv6(dst="::1")/UDP(sport=53, dport=12345)/DNS(
        qr=1, aa=1, qd=DNSQR(qname="test.com"),
        an=DNSRR(rrname="test.com", type="AAAA", rdata="2001:db8::1")
    )

    # Send the packet
    sendp(dns_resp, iface="eth0")
    print("Sent fake IPv6 DNS response for test.com -> 2001:db8::1")

if __name__ == "__main__":
    send_fake_ipv6_dns()
