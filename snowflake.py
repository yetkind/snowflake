import requests
import json
import csv

def get_ip_addresses_from_otx(domain, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {
        'X-OTX-API-KEY': api_key
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        ip_addresses = [record['address'] for record in data['passive_dns']]
        return ip_addresses
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return []

def export_to_yara(domain, ip_addresses, output_file):
    yara_rule = 'rule ' + domain.replace('.', '_') + '\n{\n'
    yara_rule += '    meta:\n'
    yara_rule += '        description = "Generated YARA rule for ' + domain + '"\n'
    yara_rule += '    strings:\n'
    for i, ip in enumerate(ip_addresses):
        yara_rule += f'        $ip{i} = "{ip}"\n'
    yara_rule += '    condition:\n'
    yara_rule += '        any of them\n}\n'
    
    with open(output_file, 'w') as f:
        f.write(yara_rule)

def export_to_spamassassin(domain, ip_addresses, output_file):
    spamassassin_rule = f"""header {domain.replace('.', '_')}_rule ALL =~ /{domain}/
describe {domain.replace('.', '_')}_rule Email from {domain}
score {domain.replace('.', '_')}_rule 5.0
tflags {domain.replace('.', '_')}_rule net
"""
    for i, ip in enumerate(ip_addresses):
        spamassassin_rule += f'body {domain.replace(".", "_")}_ip{i} eval:check_rbl_txt("spamhaus.org", "{ip}")\n'
    
    with open(output_file, 'w') as f:
        f.write(spamassassin_rule)

def export_to_csv(domain, ip_addresses, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Domain", "IP Address"])
        for ip in ip_addresses:
            writer.writerow([domain, ip])

def export_to_json(domain, ip_addresses, output_file):
    data = {
        "domain": domain,
        "ip_addresses": ip_addresses
    }
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    print("""

                                                                   
 ,---.                             ,---.,--.        ,--.           
'   .-' ,--,--,  ,---. ,--.   ,--./  .-'|  | ,--,--.|  |,-. ,---.  
`.  `-. |      \| .-. ||  |.'.|  ||  `-,|  |' ,-.  ||     /| .-. : 
.-'    ||  ||  |' '-' '|   .'.   ||  .-'|  |\ '-'  ||  \  \\   --. 
`-----' `--''--' `---' '--'   '--'`--'  `--' `--`--'`--'`--'`----' 
                                                   -yetkin 2024                

""")
    domain = input("Enter the domain: ")
    api_key = input("Enter your OTX API key: ")
    ip_addresses = get_ip_addresses_from_otx(domain, api_key)
    
    if ip_addresses:
        print(f"IP addresses for {domain}: {ip_addresses}")
        
        export_to_yara(domain, ip_addresses, 'output.yara')
        export_to_spamassassin(domain, ip_addresses, 'output.spamassassin')
        export_to_csv(domain, ip_addresses, 'output.csv')
        export_to_json(domain, ip_addresses, 'output.json')
        
        print("\n Exported to YARA, SpamAssassin, CSV, and JSON formats.")
    else:
        print("No IP addresses found or error occurred.")

if __name__ == "__main__":
    main()
