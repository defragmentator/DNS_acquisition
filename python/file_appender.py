import json
import re
from io import StringIO, BytesIO
import pycurl
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import configparser
import socket
import redis


class SQLFieldsAppender:
    def __init__(self, file, fields, destination_fields):
        self.file = file
        self.fields = fields
        self.destination_fields = destination_fields

    def _make_fields(self):
        fields_list = []
        for f in self.fields:
            fields_list.append('   ' + f[0] + ' ' + f[1] + ',\n')
        return fields_list

    def append_join(self):
        with open(self.file, 'r') as file:
            content = file.read()
            for field in self.fields:
                dotIndex = field[0].find('.')
                if dotIndex != -1:
                    pattern =  field[0][:dotIndex] + '(.*?)' + field[0][dotIndex + 1:] + '(.*?),'

                print(pattern)

                field_value = re.search(pattern, content)
                if field_value is None:
                    raise Exception('Fatal error, field: ' + field[0] + ' not found in sql!!!')
                field_value = content[field_value.regs[0][0]: field_value.regs[0][1]]
                generated = field_value + '\n'
                for d in self.destination_fields:
                    if dotIndex != -1:
                        generated += '      ' + field[0][:-1] +'_'+ d[0] + '" ' + d[1] + ',\n'
                print(generated)
                content = content.replace(field_value, generated)
                print(content)

            file.close()
            with open('./' + self.file + '_append', 'w') as dest:
                dest.writelines(content)
                dest.close()
            return content

    def append2(self):
        with open(self.file, 'r') as file:
            content = file.read()
            for field in self.fields:
                dotIndex = field[0].find('.')
                if dotIndex != -1:
                    pattern =  field[0][:dotIndex] + '(.*?)' + field[0][dotIndex + 1:] + '(.*?),'
                else:
                    pattern = field[0] + '(.*?),'
                print(pattern)
                #'Answers(.*?)dns_a(.*?),'
                field_value = re.search(pattern, content, flags=re.DOTALL)
                if field_value is None:
                    raise Exception('Fatal error, field: ' + field[0] + ' not found in sql!!!')
                field_value = content[field_value.regs[0][0]: field_value.regs[0][1]]
                generated = field_value + '\n'
                for d in self.destination_fields:
                    if dotIndex != -1:
                        generated += '      ' + field[0][dotIndex + 1:] +'_'+ d[0] + ' ' + d[1] + ',\n'
                    else:
                        generated += '   ' + field[0] + '_' + d[0] + ' ' + d[1] + ',\n'
                print(generated)
                content = content.replace(field_value, generated)
                print(content)

            file.close()
            with open('./' + self.file + '_append', 'w') as dest:
                dest.writelines(content)
                dest.close()
            return content



    def append(self):
        fields = self._make_fields()
        with open(self.file, 'r') as file:
            lines = file.readlines()
            #previous = []
            i = 0
            for field in fields:
                line_number = lines.index(field)
                print('line number ', line_number)
                previous = lines[:line_number+1].copy()
                print(previous)

                for destination_field in self.destination_fields:
                    new_column = '   ' + self.fields[i][0] + '_' + destination_field[0] + ' ' + destination_field[1] + ',\n'
                    previous.append(new_column)
                i += 1
                print(previous)
                previous += lines[line_number+1:].copy()
                lines = previous.copy()
                print(previous)
            file.close()
            with open('./temp2', 'w') as dest:
                dest.writelines(previous)
                dest.close()


class JSONConcatenater():
    def __init__(self, fields):
        config = configparser.ConfigParser()
        config.read('config.ini')

        self.fields = fields
        self.first_api_fields = eval(config['fields']['first_api_fields']) #['as_country_code', 'as_description', 'as_number']
        self.second_api_fields = eval(config['fields']['second_api_fields']) #['country', 'latitude', 'longitude', 'timezone']
        self.max_udp_timeout = float(config['udp']['max_timeout'])
        self.r = redis.Redis( decode_responses=True)

    def getFirstApi(self, ip):
        cache = self.r.get(ip+"API1")
        if cache is None:
            buffer = BytesIO()
            curl = pycurl.Curl()
            curl.setopt(curl.URL, '127.0.0.1:53661/v1/as/ip/' + ip)
            curl.setopt(curl.WRITEFUNCTION, buffer.write)
            curl.setopt(pycurl.HTTPHEADER, ["Accept: application/json"])
            curl.perform()
            status=curl.getinfo(pycurl.HTTP_CODE)
            curl.close()
            body = buffer.getvalue().decode('UTF-8')
            if status == 200:
                self.r.set(ip+"API1",body)
            return body
            #data = '{"announced": "true", "as_country_code": "US", "as_description": "GOOGLE - Google LLC", "as_number": "15169", ' \
            #        '"first_ip": "8.8.8.0", "ip": "8.8.8.8", "last_ip": "8.8.8.255"}'
            #return data
        else :
    #        print("redis hit: "+ip+" "+cache)
            return cache

    def getSecondApi(self, ip):
        cache = self.r.get(ip+"API2")
        if cache is None:
            buffer = BytesIO()
            curl = pycurl.Curl()
            curl.setopt(curl.URL, '127.0.0.1:53662/' + ip)
            curl.setopt(curl.WRITEFUNCTION, buffer.write)
            curl.setopt(pycurl.HTTPHEADER, ["Accept: application/json"])
            curl.perform()
            status=curl.getinfo(pycurl.HTTP_CODE)
            curl.close()
            body = buffer.getvalue().decode('UTF-8')
            if status == 200:
                self.r.set(ip+"API2",body)
            return body
        #return '{"country":"US","latitude":"37.751","longitude":"-97.822","timezone":"America/Chicago"}'
        else :
    #        print("redis hit: "+ip+" "+cache)
            return cache

    def reverse_ip(self, ip):
        numbers = ip.split('.')
        return numbers[3] + '.' + numbers[2] + '.' + numbers[1] + '.' + numbers[0]

    def getSpamList(self, domain, ip):
        cache = self.r.get(ip+domain)
        if cache is None:
            reversed = self.reverse_ip(ip)
            qname = reversed + domain
            try:
                data = socket.gethostbyname(qname)
                rsp = repr(data)
                rsp = int(rsp.split('.')[-1][:-1])
            #    print("jest podejrzany ip: "+str(rsp))
                self.r.set(ip+domain,rsp)
                return rsp
            except Exception as e:
                self.r.set(ip+domain,255)
                return None
        else :
            cache = int(cache)
        #    print("redis hit: "+ip+domain+" "+str(cache))
            if cache == 255:
                return None
            return cache

    def getSpamList_old(self, domain, ip):
        reversed = self.reverse_ip(ip)
        qname = dns.name.from_text(reversed + domain)
        q = dns.message.make_query(qname, dns.rdatatype.A)
        #r = dns.query.udp(q, '62.133.157.130', timeout=self.max_udp_timeout)
        r = dns.query.udp(q, '127.0.0.1', timeout=self.max_udp_timeout)
        ans = r.get_rrset(r.answer, rdclass=dns.rdataclass.IN, name=qname, rdtype=dns.rdatatype.A)
        if ans is not None:
            resp = ans.to_text()
            return int(resp.split(' ')[-1].split('.')[-1])
        return None

    def getBaracuda(self, ip):
        return self.getSpamList('.b.barracudacentral.org', ip)

    def getSpamHouse(self, ip):
        return self.getSpamList('.zen.spamhaus.org', ip)

    def getSorbs(self, ip):
        return self.getSpamList('.dnsbl.sorbs.net', ip)

    def concatenate(self, input):
        content = input
        #print(input)

        for field in self.fields:
            dotIndex = field.find('nie ma na pewno')
            #print(dotIndex)
            if dotIndex != -1:
                pattern = '"' + field[:dotIndex] + '":(.*?)"' + field[dotIndex + 1:] +'":\[(.*?)\]'
                print(pattern)
            else:
                pattern = field + '":\[(.*?)\]'
            #    print(pattern)
            field_value = re.search(pattern, content)
            if field_value is None:
                raise Exception('Fatal error, field: ' + field + ' not found in ndjosnf!!!')
            else:
                #print(field_value)
                field_value = content[field_value.regs[0][0] : field_value.regs[0][1]]
                #print(field_value)

            if dotIndex != -1:
                ip = re.search('"dns_a":\[(.*?)\]', field_value)
                ip = field_value[ip.regs[0][0]: ip.regs[0][1]]
                ip = json.loads(ip.replace('"dns_a":', ''))
            else:
                ip = field_value.split(':')[1]#.replace('"', '')
            #print('ip', ip)

            if dotIndex == -1:
                responses = {}
                index = 0
                subfield = field[dotIndex + 1:]
                ip = json.loads(ip)
                #print(ip)
                for k in self.first_api_fields:
                    responses[subfield + '_' + k] = [None] * len(ip)
                for k in self.second_api_fields:
                    responses[subfield + '_' + k] = [None] * len(ip)
                responses[subfield + '_baracuda_response_code'] = [None] * len(ip)
                responses[subfield + '_spamhaus_response_code'] = [None] * len(ip)
                responses[subfield + '_sorbs_response_code'] = [None] * len(ip)

                for i in ip:
                    if i is not None:
                        first_api_plain_response = self.getFirstApi(i)

                        second_api_plain_response = self.getSecondApi(i)

                        if first_api_plain_response is not None and first_api_plain_response.find('false') == -1:
                            first_api_json = json.loads(first_api_plain_response)
                            first_api_json['announced'] = str(first_api_json['announced'])

                            if first_api_json['announced'] != 'False':
                                for k in ['as_country_code', 'as_description']:
                                    responses[subfield + '_' + k][index] = first_api_json[k]
                        if second_api_plain_response is not None and second_api_plain_response != '':

                            second_api_json = json.loads(second_api_plain_response)
                            second_api_json['latitude'] = float(second_api_json['latitude'])
                            second_api_json['longitude'] = float(second_api_json['longitude'])

                            if not 'country' in second_api_json.keys():
                                second_api_json['country'] = None

                            for k in self.second_api_fields:
                                responses[subfield + '_' + k][index] = second_api_json[k]

                        responses[subfield + '_baracuda_response_code'][index] = self.getBaracuda(i)
                        responses[subfield + '_spamhaus_response_code'][index] = self.getSpamHouse(i)
                        responses[subfield + '_sorbs_response_code'][index] = self.getSorbs(i)


                    index += 1

                if index == len(ip):
                    # same nulle?!
                    pass

                no_spaces = json.dumps(responses).replace('{', '').replace('}', '')
                #if no_spaces.find(' ') != -1:
                #    raise Exception(' no nie!!!!!!!!!!!!!!!')

                content = content.replace(field_value,
                                          field_value + ',' + no_spaces)


                #print(content)

            else:
                first_api_plain_response = self.getFirstApi(ip)
                second_api_plain_response = self.getSecondApi(ip)

                old = json.loads(first_api_plain_response)
                print(old)
                new = {}
                for k in old.keys():
                    new[field + '_'+k] = old[k]
                print(json.dumps(new))

                old2 = json.loads(second_api_plain_response)
                new2 = {}
                for k in old2.keys():
                    new2[field + '_' + k] = old2[k]
                #print(json.dumps(new2))

                content = content.replace(field_value, field_value + ', ' + json.dumps(new).replace('{', '').replace('}', '') +
                                      json.dumps(new2).replace('{', '').replace('}', ''))
                return content

        #print(content)
        return content

