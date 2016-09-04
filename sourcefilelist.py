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

tld_list_filepath = 'datasrc/tlds-alpha-by-domain.txt'          #list of existing TLD
google_ip_list_filepath = 'datasrc/google_ip.txt'               #ip address or range of google CIDR notation
yahoo_ip_list_filepath = 'datasrc/yahoo_ip.txt'                 #ip address or range of yahoo CIDR notation
microsoft_ip_list_filepath = 'datasrc/microsoft_ip.txt'         #ip address or range of microsoft CIDR notation
alexa_list_filepath = 'datasrc/alexalist.txt'                   #alexa top 1M list (without the first line of csv file)
alexa_exception_list_filepath = 'datasrc/alexa_exception.txt'   #some domain that we want to exclude from alexa list
md5_list_filepath = 'datasrc/md5.txt'                           #MD5 of known "safe" file
sha1_list_filepath = 'datasrc/sha1.txt'                         #SHA1 of known "safe" file
sha256_list_filepath = 'datasrc/sha256.txt'                     #SHA256 of known "safe" file
