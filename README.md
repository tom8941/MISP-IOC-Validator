# MISP-IOC-Validator

The main purpose is to validate the format of the different IOC from MISP and to remove false positive by comparing these IOC to existing known false positive (known SHA1 or SHA256 of a file, ...). There is however a lot of other features available.

**Features:**
- IOC validation (format, detect false positive iocs, ...)
- Export the IOC and the result of the validation of the IOC in CEF format (to a SIEM for example)
- Send the ioc and the result of the check to a syslog server
- Validate and export YARA and SNORT rules in a file that can be automaticaly integrated to FireEye sensors or SourceFire Snort
- Send results of IOC check by mail that give the reason of the error with the IOC that didn't pass the checks.
- ...

## Prerequisite

- install of the following modules:
 - PyMISP module : https://github.com/CIRCL/PyMISP
 - Netaddr module : https://pypi.python.org/pypi/netaddr
 - Python-dumbpig : https://github.com/MrJester/python-dumbpig
 - Python yara module : https://github.com/plusvic/yara
- Create source files used in sourcefilelist.py. These files should contains the list of false positive.
 - The default list available are more or less empty, so you have to enter you own values, here ares some references :
  - http://data.iana.org/TLD/tlds-alpha-by-domain.txt
  - http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
  - http://www.nsrl.nist.gov/Downloads.htm
- Configure keys.py. Please check https://github.com/CIRCL/PyMISP for more details.
- Configure mail in checkioc.py : MAIL_FROM and MAIL_SERVER.

## Usage and Examples

**Display of the result**
```
-v, --verbose : Print the result of each test of attributes. The format used is a CEF syslog format that can be translated by a SIEM
-q, --quiet   : Suppress all outputs (Useful when running in background)
```
If none of them have been selected, you will just have outputs of what is processing (timeframe and number of ioc processed)

**Check the IOC from MISP of the last day**

Syntax is really close to the last function of PyMISP
```
parameter : -l, --last
./checkioc.py -l 1d -v
```

**Check the IOC from MISP of the last day only for domains**
```
parameter : -l, --last
parameter : -o, --only
./checkioc.py -l 1d -o domain -v
```

**Check the IOC from MISP of the last day only for domains and hostnames**
```
parameter : -l, --last
parameter : -o, --only
./checkioc.py -l 1d -o domain hostname -v
```
**Check the IOC from MISP of the last day for all type except domains and hostname**

Works like -o
```
parameter : -l, --last
parameter : -w, --without
./checkioc.py -l 1d -w domain hostname -v
```

**Which other IOC types are supported for filtering**
```
./checkioc.py --print_types
ip-src
yara
domain
hostname
...
```

**Check the IOC from MISP of a specific period in time**

In this example we are checking for all ioc from 2015-01-01 to 2016-06-01. The request to server is split in slice of 5 days between these days. Every check of these slice is separated by a little break of 10 seconds. 
```
parameter : -s, --start   date should be YYYY-MM-DD
parameter : -e, --end     date should be YYYY-MM-DD
optional parameter : -d, --day_slice   cut the timerange between start and end in slice of days define in this parameter. This allow to create smaller ioc request to the server.
optional parameter : -t, --time_wait   should be used with -d. This parameters tells the number of seconds that the program will wait before two slice defined with -d. This again in order to avoid overload of the server. This parameter is however only effective if IOC exists during such slice of time otherwise it is ignored.

./checkioc.py -s 2015-01-01 -e 2016-06-01 -d 5 -t 10 -v
```

**Check the IOC from MISP of the last day and send result using syslog**
```
parameter : -l, --last
parameter : -i IP, --ip IP        Syslog server ip
parameter : -p PORT, --port PORT  Syslog server port (udp)

./checkioc.py -l 1d -i 10.0.0.1 -p 514 -v
```

**Check the IOC from MISP of the last day and send result using syslog**
```
parameter : -l, --last
parameter : -i IP, --ip IP        Syslog server ip
parameter : -p PORT, --port PORT  Syslog server port (udp)

./checkioc.py -l 1d -i 10.0.0.1 -p 514 -v
```

**Check the IOC from MISP of the last day and export yara rules to a file**

The yara rules from MISP which are valid according to the analyser. Please note that we also consider import of modules and some other syntax as wrong because it is not compatible with FireEye for the moment.
```
parameter : -l, --last
parameter : -y YARA_EXPORT_PATH, --yara_export_path  Valid yara rules export file path 

./checkioc.py -l 1d -y /opt/valid_yara.txt
```

**Check the IOC from MISP of the last day and export snort rules to a file**

The snort rules from MISP which are valid according to the analyser. Please note that it modifies the version and the ID in order to have something locally unique that can be sent to a snort.
```
parameter : -l, --last
parameter : -z SNORT_EXPORT_PATH, --snort_export_path SNORT_EXPORT_PATH  Valid snort rules export file path 

./checkioc.py -l 1d -y /opt/valid_snort.txt
```

**Check the IOC from MISP of the last day and send the result of wrong IOC in a mail**

Don't forget to modify variables as said in the Prerequisite section.
```
parameter : -l, --last
parameter : -m MAIL, --mail MAIL Email that will receive results of wrong IOCs.
```

**Check the IOC from MISP of the last day and use a lock file to prevent multiple execution at the same time**

This function is useful when you know you can have problems with concurrent access as it is the case with the option of attribute tracking define after.
```
parameter : -l, --last
parameter : --lock LOCK  Specify a lock file to prevent multiple execution.
./checkioc.py -l 1d --lock /tmp/lockfile
```

**Check the IOC from MISP of the last day and use an history file to avoid to recheck the same IOC multiple time**

This function is useful to avoid rechecking attributes that have already been validated and that didn't change since.
The file will store the IOC uuid and his last modification time in oder to track new changes and the need of rechecking this IOC. The lock function defined above can be useful in order to avoid access conflict of this file.
```
parameter : -l, --last
parameter :  -a ATTRIBUTE_TRACKING, --attribute_tracking ATTRIBUTE_TRACKING   this is file used to track already processed IOC based on its uuid and modification date
./checkioc.py -l 1d -a /opt/ioc_tracked.txt
```

## External Source

- MISP : https://github.com/MISP/MISP
- PyMISP module : https://github.com/CIRCL/PyMISP
- Netaddr module : https://pypi.python.org/pypi/netaddr
- Python-dumbpig : https://github.com/MrJester/python-dumbpig
- yara : https://github.com/plusvic/yara
- TLDS : http://data.iana.org/TLD/tlds-alpha-by-domain.txt
