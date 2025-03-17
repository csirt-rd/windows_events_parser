import json
import os
import re
import sys
from xml.etree import ElementTree

import xmltodict
import win32evtlog


def parse(event) -> str:
    xml_content: str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
    output = xmltodict.parse(xml_content)

    binary = output.get('Event', {}).get('EventData', {}).get('Binary', None)

    if binary:
        output['Event']['EventData']['DNSPacket'] = parse_binary_dns(binary)
    
    return json.dumps(output)


def parse_binary_dns(hex_data: str) -> dict[str, str] | None:
    try:
        dns_packet = bytes.fromhex(hex_data).decode(encoding='ascii' ,errors='ignore')
        # transaction_id = hex_data[0:8]
        # flags = hex_data[8:12]
        # questions = bytes.fromhex(hex_data[12:16]).decode()
        # answer_rrs = bytes.fromhex(hex_data[16:20]).decode()
        # authority_rrs = bytes.fromhex(hex_data[20:24]).decode()
        # additional_rrs = bytes.fromhex(hex_data[24:28]).decode()
        # domain_parts = [hex_data[28:36], hex_data[36:42], hex_data[42:48], hex_data[48:56]]
        # domain = "".join([bytes.fromhex(part).decode('utf-8') for part in domain_parts])\
        #     .replace('\u0003', '')\
        #     .replace('\u0002', '')\
        #     .replace('\u000b', '')
        # ptr_part = hex_data[56:72]
        # query_type = hex_data[72:76]
        # query_class = hex_data[76:80]
        # additional_section = hex_data[80:]

        # dns_packet = {
        #     "Transaction ID": transaction_id,
        #     "Flags": flags,
        #     "Questions": questions,
        #     "AnswerRRs": answer_rrs,
        #     "AuthorityRRs": authority_rrs,
        #     "AdditionalRRs": additional_rrs,
        #     "Domain": domain,
        #     "PTRPart": ptr_part,
        #     "QueryType": query_type,
        #     "QueryClass": query_class,
        #     "AdditionalSection": additional_section
        # }

        dns_packet = re.sub(r'[^\x00-\x7F]+', ' ', dns_packet)

        return dns_packet
    except:
        return None
    

def main():
    if len(sys.argv) < 3:
        print("pass the input and output path as arguments, please")
        return

    query_handle = win32evtlog.EvtQuery(sys.argv[1], win32evtlog.EvtQueryFilePath)

    output = []

    while True:
        events = win32evtlog.EvtNext(query_handle, 1000)

        if len(events) == 0:
            break

        for event in events:
            output.append(parse(event))

    with open(sys.argv[2], '+a') as file:
        for line in output:
            file.write(f'{line}\n')


if __name__ == "__main__":
    main()
