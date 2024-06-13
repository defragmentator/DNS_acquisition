import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query


class dupa:
    def reverse_ip(self, ip):
        numbers = ip.split('.')
        return numbers[3] + '.' + numbers[2] + '.' + numbers[1] + '.' + numbers[0]

    def getSpamList(self, domain, ip):
        reversed = self.reverse_ip(ip)
        qname = dns.name.from_text(reversed + domain)
        q = dns.message.make_query(qname, dns.rdatatype.A)
        r = dns.query.udp(q, '8.8.8.8')
        ans = r.get_rrset(r.answer, rdclass=dns.rdataclass.IN, name=qname, rdtype=dns.rdatatype.A)
        if ans is not None:
            resp = ans.to_text()
            return resp.split(' ')[-1].split('.')[-1]
        return None

    def getBaracuda(self, ip):
        return self.getSpamList('.b.barracudacentral.org', ip)

    def getSpamHouse(self, ip):
        return self.getSpamList('.zen.spamhaus.org', ip)

    def getSorbs(self, ip):
        return self.getSpamList('.dnsbl.sorbs.net', ip)


print(dupa().reverse_ip('5.184.245.148'))
print(dupa().getBaracuda('5.184.245.148'))
