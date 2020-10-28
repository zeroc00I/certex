import certstream
import argparse
import sys

BLUE='\033[94m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CLEAR='\x1b[0m'

print(BLUE + "Certex[1.0] by ARPSyndicate" + CLEAR)
print(YELLOW + "monitors certificate transparency logs" + CLEAR)

if len(sys.argv)<2:
	print(RED + "[!] ./certex --help" + CLEAR)
	sys.exit()
else:
    parser=argparse.ArgumentParser()
    parser.add_argument("-d", "--domains", default=[], type=str, nargs='+', help="domains to be monitored")
    parser.add_argument("-o", "--output", type=str, help="output file")    

args = parser.parse_args()
if not args.domains:
    parser.error(RED + "[!] list of domains not given" + CLEAR)
domains = args.domains
output = args.output

print(YELLOW + "[*] monitoring for: " + str(domains) + CLEAR)

def process(message, context):
    if message['message_type'] == "heartbeat":
        return
    if message['message_type'] == "certificate_update":
        cert_domains = message['data']['leaf_cert']['all_domains']
        if len(cert_domains) != 0:
           identify(cert_domains)
    return

def identify(cert_domains):
    found = []
    for doms in cert_domains:
        if any(doms.endswith("."+dom) for dom in domains):
            found.append(doms.replace("*.",""))
            
    found = list(set(found))
    for dom in found:
        print(BLUE + "[+] "+ dom + CLEAR)
    if args.output:
        with open(output, 'a') as f:
            f.writelines("%s\n" % line for line in found)

certstream.listen_for_events(process, url='wss://certstream.calidog.io/')