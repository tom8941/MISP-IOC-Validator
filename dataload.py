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

from sourcefilelist import *

def import_external_sources(attribute_set):
    '''Returns dict of sets where each set contains values of the files referenced in sourcefilelist.

    attribute_set -- set of misp attribute types that would be concerned by the import.
    '''
    data = {}
    data['tld'] = frozenset()
    data['googleip'] = frozenset()
    data['yahooip'] = frozenset()
    data['microsoftip'] = frozenset()
    data['alexa_all'] = frozenset() 
    data['alexa_except'] = frozenset()
    data['alexa_hashes'] = frozenset()
    data['alexa_except_hashes'] = frozenset()
    data['md5'] = frozenset()
    data['sha1'] = frozenset()
    data['sha256'] = frozenset()

    data['tld'] = frozenset(line.lower().strip() for line in open(tld_list_filepath))
    data['googleip'] = frozenset(line.strip() for line in open(google_ip_list_filepath))
    data['yahooip'] = frozenset(line.strip() for line in open(yahoo_ip_list_filepath))
    data['microsoftip'] = frozenset(line.strip() for line in open(microsoft_ip_list_filepath))
    data['alexa_all'] = frozenset(line.lower().strip() for line in open(alexa_list_filepath))  #full alexa list
    data['alexa_except'] = frozenset(line.lower().strip() for line in open(alexa_exception_list_filepath)) #dyndns ips
    data['yara_export_except'] = frozenset(line.strip() for line in open(yara_export_exception_list_filepath)) #list of names of yara rules to discard from export

    data['alexa'] = data['alexa_all'] - data['alexa_except'] # remove elements from except list
   
    if 'md5' in attribute_set or 'filename|md5' in attribute_set:
        data['md5'] = frozenset(line.lower().strip() for line in open(md5_list_filepath))

    if 'sha1' in attribute_set or 'filename|sha1' in attribute_set:
        data['sha1'] = frozenset(line.lower().strip() for line in open(sha1_list_filepath))

    if 'sha256' in attribute_set or 'filename|sha256' in attribute_set:
        data['sha256'] = frozenset(line.lower().strip() for line in open(sha256_list_filepath))

    return data
