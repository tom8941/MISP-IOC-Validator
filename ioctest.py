#!/usr/bin/env python
# -*- coding: utf-8 -*-

# MISP-IOC-Validator - Validate IOC from MISP ; Export results and iocs to SIEM and sensors using syslog and CEF format
#
# Copyright (C) 2016 Thomas Hilt
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from netaddr import IPNetwork, IPAddress
import json
import os
import yara
import dumbpig
import random
import string
import time
import datetime
import re
import csv

##############
###Constant###
##############

DOMAIN_FORMAT = '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$' # RFC1123
HOSTNAME_FORMAT = '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$' # RFC1123

DOMAIN_REGEX = re.compile(DOMAIN_FORMAT)
HOSTNAME_REGEX = re.compile(HOSTNAME_FORMAT)

DOMAIN_ALLOWED_CHARS_SET = frozenset(['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','.'])
HOSTNAME_ALLOWED_CHARS_SET =  frozenset(['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','.'])
URL_ALLOWED_CHARS_SET =  frozenset(['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','.','_','~',':','/','?','#','[',']','@','!','$','&','\'','(',')','*','+',',',';','=','%'])
TRUST_DOMAIN = '    '  # change me

#allowed_attribute_set = set(['domain','comment','other','filename','md5','url','patttern-in-file','regkey','regkey|value','mutex','ip-src','ip-dst','hostname','email-src','filename|sha1','filename|md5','pattern-in-traffic','malware-sample','link','sha1','AS','text','attachment','user-agent','filename|sha256','pattern-in-memory','http-method','sha256','vulnerability','email-subject','email-dst','email-attachment','snort','yara','named pipe','target-org','target-location','uri','domain|ip','threat-actor'])

allowed_attribute_set = set(['domain','url','ip-src','ip-dst','hostname','filename|sha1','sha1','filename|md5','md5','filename|sha256','sha256','snort','yara','text'])
to_ids_attribute_set = set(['filename|sha1','sha1','filename|md5','md5','filename|sha256','sha256','snort','yara'])
no_to_ids_attribute_set = set(['link','threat-actor','vulnerability','text','AS','http-method'])

lowercase_attribute_set = set(['domain','hostname','md5','sha1','sha256','filename|md5','filename|sha1','filename|sha256'])

snort_sid_regexp = re.compile('sid:( )*\w*;')
snort_rev_regexp = re.compile('rev:( )*\w*;')

attribute_processed = set()
attribute_status_dict = {}

############################################
########## General Test Functions ##########
############################################

def _is_ip_private(ip):
    '''Check if the ip given is in RFC1918 IP range (Private ip).

    ip -- ip to check in string format.
    '''
    return IPAddress(ip).is_private()

def _is_ip_in_set(ip, ip_set):
    '''Check if the ip given is in a ip range contained in ip_set.

    ip -- ip to check in string format.
    ip_set -- set of ip range in string format.
    '''
    return any(IPAddress(ip) in IPNetwork(range) for range in ip_set)

def _is_tld_valid(name,valid_tld_string_set):
    '''Check if name contains a valid tld string given by valid_tld_string_set.

    name -- hostname or domain to check (case sensitive).
    valid_tld_string_set -- list of valid TLD.
    '''
    tld_domain = name.rpartition('.')[-1]
    return tld_domain in valid_tld_string_set

def _has_invalid_characters(string, valid_char_set):
    '''Check if a string contains characters that do not belongs to valid_char_set.

    string -- string to check.
    valid_char_set -- set of valid characters.
    '''
    strcharset = frozenset(string)
    return not strcharset.issubset(valid_char_set)

def _is_in_domain(name,top_domain_split):
    '''Check if name belongs to a specific top domain given by top_domain.

    name -- name to check (case sensitive).
    top_domain_split -- list of string that contains the top level domain (case sensitive).
    '''
    dom_list = name.split('.')

    dom_list_len = len(dom_list)
    i = dom_list_len - 1 

    for dom in reversed(top_domain_split):
        if i >= 0:
            if dom_list[i] != dom:
                return False
        else:
            return True

        i -= 1

    return True

def _is_in_domain_set(name,domain_set):
    '''Check if name belongs to domain_set.

    name -- name to check (case sensitive).
    domain_set -- set of domain to compare (case sensitive).
    '''
    #return any(_is_in_domain(name,domain) for domain in split_domain_set)
    dom_list = name.split('.')

    dompart = name.split('.')
    currdom = '' # domain build progressively by adding one by one top domain

    i=0 # treat the first part of the list that doesn't need '.'

    for part in reversed(dompart):
        if i == 0:
            currdom = part
            i = 1
        else:
            currdom = part + '.' + currdom

        if currdom in domain_set:
            return True

    return False

def _is_valid_md5(checksum):
    '''Check if the md5 given is valid.

    checksum -- checksum of the file to check.
    '''

    return re.match('([a-fA-F\d]{32})',checksum)

def _is_valid_sha1(checksum):
    '''Check if the sha1 given is valid.

    checksum -- checksum of the file to check.
    '''

    return re.match('([a-fA-F\d]{40})',checksum)

def _is_valid_sha256(checksum):
    '''Check if the sha256 given is valid.

    checksum -- checksum of the file to check.
    '''

    return re.match('([a-fA-F\d]{64})',checksum)

def _is_empty_file_md5(checksum):
    '''Check if the md5 given is the one of a void file.

    checksum -- checksum of the file to check (case sensitive).
    '''
    return checksum == 'd41d8cd98f00b204e9800998ecf8427e'

def _is_empty_file_sha1(checksum):
    '''Check if the sha1 given is the one of a void file.

    checksum -- checksum of the file to check (case sensitive).
    '''
    return checksum == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

def _is_empty_file_sha256(checksum):
    '''Check if the sha256 given is the one of a void file.

    checksum -- checksum: checksum of the file to check (case sensitive).
    '''
    return checksum == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

def _is_checksum_in_set(checksum,set):
    '''Check if a specific checksum belongs to a specific set.

    checksum -- checksum that is tested (case sensitive).
    set -- set of checksum to compare with the tested one.
    '''
    return checksum in set

def _is_name_length_valid(domain_name):
    '''Check if the length of the name is valid according to RFC1123.

    domain_name -- domain name to check
    '''
    if len(domain_name) > 253:
        return False
    else:
        label_list = domain_name.split('.')
        if any(len(l)>63 for l in label_list):
            return False
        else:
            return True

def _is_protocol_valid(url):
    '''Check if the url given start with a valid protocol (http://, https:// or ftp://).

    url -- url to check
    '''
    return url.startswith('http://') or url.startswith('https://') or url.startswith('ftp://')

def _is_slow_yara_rule(rule):
    '''Check if the yara rule given is matching a slow yara rule pattern.

    rule -- YARA rule to test.

    '''
    return re.match('\$[^\s][\s]*=[\s]*(\/[^\/]{1,4}[^\\]\/|\"[^\"]{1,4}\"|\{[0-9A-Fa-f\s]{2,16}\})',rule)

def _is_yara_rule_invalid(rule):
    '''Check if the yara rule given is invalid by trying to compile it.

    rule -- YARA rule to test.
    '''
    try:
        yara.compile(source = rule , includes=False, error_on_warning=True)
        return None
    except Exception as e:
        return str(e)

def _is_snort_rule_invalid(rule):
    '''Check if the snort rule given is invalid by trying to compile it.

    rule -- Snort rule to test.
    '''
    filepath = '/tmp/tmp_' + ''.join(random.choice(string.lowercase) for i in range(8))
    f = open(filepath, "w")
    f.write(rule)
    f.close()

    if not rule.startswith('alert'):
        return 'Snort rule does not start with "alert"'

    if "threshold" in rule:
        return 'threshold in snort rule is deprecated'

    dp = dumbpig.RuleChecker()

    dp.set_rule_file(filepath)
    dp.test_rule_file()
    os.remove(filepath)

    result = json.dumps(dp.json_output()).encode('utf8').decode('string_escape')

    if (result == '"{}"'):
        return None
    else:
        return result

############################################
######## Attribute Check Functions #########
############################################

def _check_ipSrc(event_dict, attribute_dict, datasrc_dict):
    '''Check the source ip validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if _is_ip_private(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is a private ip address'
        return resultdict

    if _is_ip_in_set(value, datasrc_dict['googleip']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is an IP from Google'
        return resultdict

    if _is_ip_in_set(value, datasrc_dict['yahooip']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is an IP from Yahoo'
        return resultdict

    if _is_ip_in_set(value, datasrc_dict['microsoftip']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is an IP from Microsoft'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_ipDst(event_dict, attribute_dict, datasrc_dict):
    '''Check the destination ip validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if _is_ip_private(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is a private ip address'
        return resultdict

    if _is_ip_in_set(value, datasrc_dict['googleip']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is an IP from Google'
        return resultdict

    if _is_ip_in_set(value, datasrc_dict['yahooip']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is an IP from Yahoo'
        return resultdict

    if _is_ip_in_set(value, datasrc_dict['microsoftip']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is an IP from Microsoft'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_domain(event_dict, attribute_dict, datasrc_dict):
    '''Check the domain validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if not _is_name_length_valid(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'lengths of name and labels are not valid'
        return resultdict

    if _has_invalid_characters(value,DOMAIN_ALLOWED_CHARS_SET):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'characters used are invalid'
        return resultdict

    if not DOMAIN_REGEX.match(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is not matching RFC1123'
        return resultdict

    if _is_in_domain(value,TRUST_DOMAIN):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it belongs to a TRUST domain'
        return resultdict

    if not _is_tld_valid(value, datasrc_dict['tld']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'there is no valid TLD'
        return resultdict

    if _is_in_domain_set(value, datasrc_dict['alexa']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it belongs to an alexa top 1M domain'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_hostname(event_dict, attribute_dict, datasrc_dict):
    '''Check the hostname validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''

    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if not _is_name_length_valid(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'lengths of name and labels are not valid'
        return resultdict

    if _has_invalid_characters(value,HOSTNAME_ALLOWED_CHARS_SET):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'characters used are invalid'
        return resultdict

    if not HOSTNAME_REGEX.match(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is not matching RFC1123'
        return resultdict

    if _is_in_domain(value,TRUST_DOMAIN):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it belongs to a TRUST domain'
        return resultdict

    if not _is_tld_valid(value, datasrc_dict['tld']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'there is no valid TLD'
        return resultdict

    if _is_in_domain_set(value, datasrc_dict['alexa']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it belongs to an alexa top 1M domain'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_url(event_dict, attribute_dict):
    '''Check the url validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if not _is_protocol_valid(value): 
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'protocol used is not valid'
        return resultdict

    if _has_invalid_characters(value,URL_ALLOWED_CHARS_SET):  #TEST ID31
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'characters used are invalid'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_md5(event_dict, attribute_dict, datasrc_dict):
    '''Check the md5 validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if '|' in value: #if format is filename|checksum
        value = value.split('|')[1] #retreive only checksum for tests
        
    if not _is_valid_md5(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum is not valid'
        return resultdict

    if _is_empty_file_md5(value):  
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum is the one of an empty file'
        return resultdict

    if _is_checksum_in_set(value,datasrc_dict['md5']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum belongs to NSRL List'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_sha1(event_dict, attribute_dict, datasrc_dict):
    '''Check the sha1 validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if '|' in value: #if format is filename|checksum
        value = value.split('|')[1] #retreive only checksum for tests

    if not _is_valid_sha1(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum is not valid'
        return resultdict

    if _is_empty_file_sha1(value):  
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum is the one of an empty file'
        return resultdict

    if _is_checksum_in_set(value,datasrc_dict['sha1']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum belongs to NSRL List'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_sha256(event_dict, attribute_dict, datasrc_dict):
    '''Check the sha256 validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    if '|' in value: #if format is filename|checksum
        value = value.split('|')[1] #retreive only checksum for tests

    if not _is_valid_sha256(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum is not valid'
        return resultdict

    if _is_empty_file_sha256(value): 
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum is the one of an empty file'
        return resultdict

    if _is_checksum_in_set(value,datasrc_dict['sha256']):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'checksum belongs to NSRL List'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_yara(event_dict, attribute_dict):
    '''Check the yara validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    error = _is_yara_rule_invalid(value)

    if error:
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'YARA rule is not valid : ' + error
        return resultdict

    if _is_slow_yara_rule(value):
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'it is a slow performing yara rule'
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

def _check_snort(event_dict, attribute_dict):
    '''Check the snort validity.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    '''
    value = attribute_dict['value']
    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    error = _is_snort_rule_invalid(value)

    if error:
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'Snort rule is not valid : ' + error
        return resultdict

    resultdict['result'] = 'OK'
    resultdict['reason'] = 'attribute has been validated'
    return resultdict

############################################
############## Get Functions ###############
############################################

def _get_event_elements(event):
    '''Returns a dict object that contains elements of an event.

    event -- json snippet that contains an event.
    '''
    event_id = json.dumps(event['id']).encode('utf8').decode('string_escape')
    event_id = event_id[1::] # remove first "
    event_id = event_id[:-1] # remove last "

    event_uuid = json.dumps(event['uuid']).encode('utf8').decode('string_escape')
    event_uuid = event_uuid[1::] # remove first "
    event_uuid = event_uuid[:-1] # remove last "

    event_time = json.dumps(event['date']).encode('utf8').decode('string_escape')
    event_time = event_time[1::] # remove first "
    event_time = event_time[:-1] # remove last "
    event_time = str(int(time.mktime(time.strptime(event_time, "%Y-%m-%d")))*1000)

    event_description = json.dumps(event['info']).encode('utf8').decode('string_escape')
    event_description = event_description[1::] # remove first "
    event_description = event_description[:-1] # remove last "

    event_source = json.dumps(event['Orgc']['name']).encode('utf8').decode('string_escape')
    event_source = event_source[1::] # remove first "
    event_source = event_source[:-1] # remove last "

    threat_level = json.dumps(event['threat_level_id']).encode('utf8').decode('string_escape')
    threat_level = threat_level[1::] # remove first "
    threat_level = threat_level[:-1] # remove last "

    return dict([('id',event_id),('uuid',event_uuid),('date',event_time),('info',event_description),('Orgcname',event_source),('threat_level_id',threat_level)])

def _get_attribute_elements(attribute):
    '''Returns a dict object that contains elements of an attribute.

    attribute -- json snippet that contains an attribute.
    '''
    attribute_id = json.dumps(attribute['id']).encode('utf8').decode('string_escape')
    attribute_id = attribute_id[1::]
    attribute_id = attribute_id[:-1]

    attribute_type = json.dumps(attribute['type']).encode('utf8').decode('string_escape')
    attribute_type = attribute_type[1::] # remove first "
    attribute_type = attribute_type[:-1] # remove last "

    value = json.dumps(attribute['value']).encode('utf8').decode('string_escape')
    value = value[1::] # remove first "
    value = value[:-1] # remove last "

    if attribute_type in lowercase_attribute_set:
        value = value.lower()

    to_ids = json.dumps(attribute['to_ids']).encode('utf8').decode('string_escape')

    attribute_uuid  = json.dumps(attribute['uuid']).encode('utf8').decode('string_escape')
    attribute_uuid  = attribute_uuid [1::] # remove first "
    attribute_uuid  = attribute_uuid [:-1] # remove last "

    attribute_category = json.dumps(attribute['category']).encode('utf8').decode('string_escape')
    attribute_category = attribute_category[1::]
    attribute_category = attribute_category[:-1]

    if attribute_type == 'snort':
        value = value.replace('\n\r','')
        value = value.replace('\n','')
        value = value.replace('\r','')
        snort_new_sid = 990000000 + int(attribute_id) # Local snort rules sid start at 1000000
        value = snort_sid_regexp.sub('sid:' + str(snort_new_sid) + ';',value)
        value = snort_rev_regexp.sub('rev:1;',value)

    return dict([('id',attribute_id), ('value',value), ('type',attribute_type), ('to_ids', to_ids), ('uuid', attribute_uuid ), ('category',attribute_category)])

############################################
############## Main Functions ##############
############################################

def check_attribute(event_dict, attribute_dict, datasrc_dict, allowed_attribute_set, attribute_status_dict):
    '''Check attribute validity defined by dicts of values.

    event_dict -- dict that contains event details.
    attribute_dict -- dict that contains attribute details.
    datasrc_dict -- dict that contains data source sets used for checks.
    attribute_status_dict -- define the file used to export valid yara rules.
    allowed_attribute_set -- set that contains the misp attibute types that would be checked.
    '''
    attribute_type = attribute_dict['type']
    to_ids =  attribute_dict['to_ids']

    resultdict = {}
    resultdict['event_dict'] = event_dict
    resultdict['attribute_dict'] = attribute_dict

    try:
        if (not attribute_dict['uuid'] in attribute_status_dict.keys()) or (attribute_status_dict[attribute_dict['uuid']] != event_dict['date']): # attribute absent or outdated
            if attribute_type in allowed_attribute_set and attribute_dict['uuid'] not in attribute_processed:
                attribute_status_dict[attribute_dict['uuid']] = event_dict['date']
                attribute_processed.add(attribute_dict['uuid']) #add to list of already processed attribute
                if to_ids in 'true' or attribute_type == 'yara' or attribute_type == 'snort': #snort and yara should always be in to_ids. Because of too many mistakes, we have to do that
                    if attribute_type in no_to_ids_attribute_set:
                        resultdict['result'] = 'NOK'
                        resultdict['reason'] = 'incoherent True value for to_ids associated to ' + attribute_type
                        return resultdict

                    if attribute_type == 'ip-src':
                        return _check_ipSrc(event_dict, attribute_dict, datasrc_dict)
    
                    elif attribute_type == 'ip-dst':
                        return _check_ipDst(event_dict, attribute_dict, datasrc_dict)

                    elif attribute_type == 'domain':
                        return _check_domain(event_dict, attribute_dict, datasrc_dict)

                    elif attribute_type == 'hostname':
                        return _check_hostname(event_dict, attribute_dict, datasrc_dict)

                    elif attribute_type == 'url':
                        return _check_url(event_dict, attribute_dict)

                    elif attribute_type == 'md5' or attribute_type == 'filename|md5':
                        return _check_md5(event_dict, attribute_dict, datasrc_dict)
 
                    elif attribute_type == 'sha1' or attribute_type == 'filename|sha1':
                        return _check_sha1(event_dict, attribute_dict, datasrc_dict)

                    elif attribute_type == 'sha256' or attribute_type == 'filename|sha256':
                        return _check_sha256(event_dict, attribute_dict, datasrc_dict)

                    elif attribute_type == 'yara':
                        return _check_yara(event_dict, attribute_dict)

                    elif attribute_type == 'snort':
                        return _check_snort(event_dict, attribute_dict)
                else:
                    if attribute_type in to_ids_attribute_set:
                        resultdict['result'] = 'NOK'
                        resultdict['reason'] = 'incoherent False value for to_ids associated to ' + attribute_type
                        return resultdict
                    else:
                        resultdict['result'] = 'NOK'
                        resultdict['reason'] = 'to_ids value is set to False'
                        return resultdict
            else:
                return None
        else:
            return None
         
    except Exception as e:
        resultdict['result'] = 'NOK'
        resultdict['reason'] = 'attribute is badly formatted and generates an exception' + str(e)
        return resultdict

def check_attributes(json_events, datasrc_dict, allowed_attribute_set, attribute_status_dict):
    '''Check attributes validity from a list of events in json format.

    json_events -- json of the events with attributes that should be checked.
    datasrc_dict -- dict that contains data source sets used for checks.
    allowed_attribute_set -- set that contains the misp attibute types that would be checked.
    attribute_status_dict -- define the file used to export valid yara rules.
    '''

    for i in range(len(json_events)):
        for j in range(len(json_events[i]['Event']['Attribute'])):
            event = json_events[i]['Event']
            attribute = json_events[i]['Event']['Attribute'][j]

            event_dict = _get_event_elements(event)
            attribute_dict = _get_attribute_elements(attribute)

            yield check_attribute(event_dict, attribute_dict, datasrc_dict, allowed_attribute_set, attribute_status_dict)

def track_attributes(json_events, allowed_attribute_set, attribute_status_dict):
    '''Check attributes validity from a list of events in json format.

    json_events -- json of the events with attributes that should be checked.
    allowed_attribute_set -- set that contains the misp attibute types that would be checked.
    attribute_status_dict -- define the file used to export valid yara rules.
    '''

    for i in range(len(json_events)):
        for j in range(len(json_events[i]['Event']['Attribute'])):
            event = json_events[i]['Event']
            attribute = json_events[i]['Event']['Attribute'][j]

            event_dict = _get_event_elements(event)
            attribute_dict = _get_attribute_elements(attribute)

            attribute_type = attribute_dict['type']

            if (not attribute_dict['uuid'] in attribute_status_dict.keys()) or (attribute_status_dict[attribute_dict['uuid']] != event_dict['date']): # attribute absent or outdated
                if attribute_type in allowed_attribute_set and attribute_dict['uuid'] not in attribute_processed:
                    attribute_status_dict[attribute_dict['uuid']] = event_dict['date']
                    attribute_processed.add(attribute_dict['uuid']) #add to list of already processed attribute
                    yield True

