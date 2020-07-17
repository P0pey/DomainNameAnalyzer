# DomainName Analyzer

Scripts create during my second year internship at Grant Thornton. The goal is to scan an analyze a domain name with nmap, whois, ...

## Installation

### Requirements:

  - [Python](https://www.python.org/): Python version 3.8
  - [pip](https://pip.pypa.io/en/stable/installing/)
  
### Packages

  - [python-nmap](https://pypi.org/project/python-nmap/): !!! install [nmap](https://nmap.org/)
  - [python-whois](https://pypi.org/project/python-whois/)
  - [dnspython3](https://pypi.org/project/dnspython3/)

You can install these modules in two ways:

  - Using pip requirements file
  ```
  $ pip install -r requirements.txt
  ```
  
  - Using the Main.py script
  ```
  $ python3.8 Main.py --install all
  ```
  
## Usage
First of all, setup a virtualenv
```
$ python -m venv venv
$ source venv/bin/activate
```

This small application need a domain name. You can also define a number of port to test (default: 1000 / max: 65535)
```
$ python3.8 Main.py -d <domain.name> -d <ports>

Or

$ python3.8 Main.py -d <domain.name>
```

This script saves logs for each steps and save different output in XML and CSV.

## Documentations

### Help Page
```
Usage:
  
  -i --install [all]: Install packages:
      $ Main.py -i all
  
  -d --domain [domain.name]: Give the script the domain name
      $ Main.py -d google.com
      
  -p --ports [ports]: Give the number of ports to test. Default: 1000. Maximum: 65535
      $ Main.py -p 100
      
Example:

  $ Main.py -d google.com -p 1000
```

### ScannerIP

Use the nmap module. The goal is to scan all ports of all IP from the domain.

### ScannerServer

Use the dns module of python to catch all NS and MX server from the domain.

## ScannerSubdomain

Extracts all subdomain from the domain.

## ScannerWhois

Brings diffents informations on all subdomain like location, the creation date,...
