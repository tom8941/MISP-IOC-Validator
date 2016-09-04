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

import json
import time

MISP_VERSION = ""

_FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

_LEVEL = {
    'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

_MAX_VAL_SIZE = 100

def _get_partial_syslog_message(message,level='info',facility='daemon'):
    '''Returns a syslog formatted message without date and host information.

    message -- message that should be formatted to syslog format.
    level -- syslog level tag.
    facility -- syslog facility tag.
    '''
    level = _LEVEL[level]
    facility = _FACILITY[facility]
    message = '<%d>misp-daemon.info: %s' % (level + facility*8, message)
    return message

def _get_truncated_value(value):
    '''Returns a truncated value of data with __TRUNCATED concatenated at the end if data length is superior to global variable _MAX_VAL_SIZE.

    value -- string that should be truncated.
    '''
    global _MAX_VAL_SIZE
    return (value[:_MAX_VAL_SIZE] + '__TRUNCATED') if len(value) > _MAX_VAL_SIZE else value


def _get_yara_signature_name(rule):
    '''Returns the signature name part of a yara rule

    rule -- contains the yara rule.
    '''
    i = rule.find('rule ') + 5
    j = rule.find(':')
    rule = rule[i:j]
    rule = rule.replace(' ','')
    return rule

def get_CEF_syslog(device_version='0',cef_event_dict=None, cef_attribute_dict=None, result=None, reason=None):
    '''Returns a CEF formatted line within a partial syslog message.
       This syslog format is partial as date and host information are discarded.
       It looks to be the only way to make this logs recognized by Arcsight. FireEye appliances are doing the same with their CEF.

    device_version -- version of the MISP instance. (default '0')
    cef_event_dict -- dict that contains event details. (default None)
    cef_attribute_dict -- dict that contains attribute details. (default None)
    result -- result of the IOC analysis (OK or NOK). (default None)
    reason -- reason that explains the result of the analysis. (default None) 
    '''

    filename = ''
    filehash = ''
    destip = ''

    event_id = cef_event_dict['id']
    event_time = cef_event_dict['date']
    event_description = cef_event_dict['info']

    event_source = cef_event_dict['Orgcname']
    threat_level = cef_event_dict['threat_level_id']

    attribute_id = cef_attribute_dict['id']
    value = cef_attribute_dict['value']

    attribute_type = cef_attribute_dict['type']
    attribute_uuid = cef_attribute_dict['uuid']
    attribute_category = cef_attribute_dict['category']
    to_ids = cef_attribute_dict['to_ids']

    if attribute_type  == 'filename|md5' or attribute_type == 'filename|sha1' or attribute_type == 'filename|sha256':
        filename = value.split('|')[0]
        filehash = value.split('|')[1]

    elif attribute_type  == 'md5' or attribute_type == 'sha1' or attribute_type == 'sha256':  #only hash
        filehash = value

    elif attribute_type  == 'filename':   #only filename
        filename = value

    if attribute_type  == 'ip-src' or attribute_type  == 'ip-dst':
        destip = value

    if attribute_type  == 'yara':
        value = _get_yara_signature_name(value)

    #truncate big strings if too long

    #value = _get_truncated_value(value)

    event_description = _get_truncated_value(event_description)
    reason = _get_truncated_value(reason)

    #header

    # escape '|' and '\' for header
    attribute_type = attribute_type.replace('\\','\\\\').replace('|','\|').replace('\n',' ').replace('\r',' ')
    event_description = event_description.replace('\\','\\\\').replace('|','\|').replace('\n',' ').replace('\r',' ')
    filename = filename.replace('\\','\\\\').replace('|','\|').replace('\n',' ').replace('\r',' ')

    cef_string = 'CEF:0|MISP|ValidityCheck|'
    cef_string += device_version + '|'
    cef_string += attribute_type + '|'
    cef_string += event_description + '|'
    cef_string += threat_level + '|'

    #Extension

    # escape '\' and '=' for extensions
    value = value.replace('\\','\\\\').replace('=','\=')
    event_source = event_source.replace('\\','\\\\').replace('=','\=')
    attribute_category = attribute_category.replace('\\','\\\\').replace('=','\=')
    result = result.replace('\\','\\\\').replace('=','\=')
    filename = filename.replace('\\','\\\\').replace('=','\=')

    cef_string += 'externalId=' + attribute_id
    cef_string += ' msg=' + value
    cef_string += ' act=' + event_source
    cef_string += ' cn1=' + event_id

    if to_ids in 'true':
        cef_string += ' cn2=' + '1'
    else:
        cef_string += ' cn2=' + '0'

    cef_string += ' cs1=' + attribute_uuid
    cef_string += ' cs4=' + attribute_category
    cef_string += ' cs5=' + result
    cef_string += ' deviceCustomDate1=' + event_time
    cef_string += ' dst=' + destip
    cef_string += ' fname=' + filename
    cef_string += ' fileHash=' + filehash
    cef_string += ' reason=' + reason

    return _get_partial_syslog_message(cef_string)

