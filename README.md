# MISP-IOC-Validator

The main purpose is to validate the format of the different IOC from MISP and to remove false positive by comparing these IOC to existing known false positive (known SHA1 or SHA256 of a file, ...). There is however a lot of other features available.

**Features:**
- IOC validation (format, detect false positive iocs, ...)
- Export the IOC and the result of the validation of the IOC in CEF format (to a SIEM for example)
- Send the ioc and the result of the check to a syslog server
- Validate and export YARA and SNORT rules in a file that can be automaticaly integrated to FireEye sensors or SourceFire Snort
- Send results by mail
- ...

## Prerequiste

- install of the following modules:
 - PyMISP module : https://github.com/CIRCL/PyMISP
 - Netaddr module : https://pypi.python.org/pypi/netaddr
 - Python-dumbpig : https://github.com/MrJester/python-dumbpig
- Create source files used in sourcefilelist.py. These files should contains the list of false positive.
 
I will try to create a setup file when possible.

More information coming soon... 

## External Source

- MISP : https://github.com/MISP/MISP
- PyMISP module : https://github.com/CIRCL/PyMISP
- Netaddr module : https://pypi.python.org/pypi/netaddr
- Python-dumbpig : https://github.com/MrJester/python-dumbpig
