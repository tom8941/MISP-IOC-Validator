# MISP-IOC-Validator

The main purpose is to validate format of the different IOC from MISP and to remove false positive by comparing these IOC to existing known false positive. There is however a lot of other features are available.

**Features:**
- IOC validation (format, detect false positive iocs, ...)
- Export the IOC and the result of the validation of the IOC in CEF format (to a SIEM for example)
- Send the ioc and the result of the check to a syslog server
- Validate and export YARA and SNORT rules in a file that can be automaticaly integrated to FireEye sensors or SourceFire Snort
- Send results by mail
- ...

More information coming soon... 

## External Source

MISP : https://github.com/MISP/MISP
PyMISP module : https://github.com/CIRCL/PyMISP
Netaddr module : https://pypi.python.org/pypi/netaddr
Python-dumbpig : https://github.com/MrJester/python-dumbpig
