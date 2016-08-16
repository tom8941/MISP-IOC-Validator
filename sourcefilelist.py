#!/usr/bin/env python
# -*- coding: utf-8 -*-

tld_list_filepath = 'datasrc/tlds-alpha-by-domain.txt'          #list of existing TLD
google_ip_list_filepath = 'datasrc/google_ip.txt'               #ip address or range of google CIDR notation
yahoo_ip_list_filepath = 'datasrc/yahoo_ip.txt'                 #ip address or range of yahoo CIDR notation
microsoft_ip_list_filepath = 'datasrc/microsoft_ip.txt'         #ip address or range of microsoft CIDR notation
alexa_list_filepath = 'datasrc/alexalist.txt'                   #alexa top 1M list (without the first line of csv file)
alexa_exception_list_filepath = 'datasrc/alexa_exception.txt'   #some domain that we want to exclude from alexa list
md5_list_filepath = 'datasrc/md5.txt'                           #MD5 of known "safe" file
sha1_list_filepath = 'datasrc/sha1.txt'                         #SHA1 of known "safe" file
sha256_list_filepath = 'datasrc/sha256.txt'                     #SHA256 of known "safe" file
