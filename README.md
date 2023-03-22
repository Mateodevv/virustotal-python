# virustotal-python
A very simple implementation of the VirusTotal V3 API. You can examine files/urls/domains/IPs quickly by simply passing the filepath.

## Installation

```pip install vtpython```

## Quickstart


``` 
from vtpython import VirusTotalClient

client = VirtusTotalClient('YOUR-API-KEY')

file_report = client.get_file_report('PATH/TO/FILE')

url_report = client.get_url_report('PATH/TO/FILE')

domain_report = client.get_domain_report('PAATH/TO/FILE')

ip_report = client.get_ip_address_report('PATH/TO/FILE')

```
