#!/usr/bin/env python
# -*- coding: utf-8 -*-

tld_list_filepath = '/opt/tlds-alpha-by-domain.txt'          #list of existing TLD
google_ip_list_filepath = '/opt/google_ip.txt'               #ip address or range of google CIDR notation 
yahoo_ip_list_filepath = '/opt/yahoo_ip.txt'                 #ip address or range of yahoo CIDR notation
microsoft_ip_list_filepath = '/opt/microsoft_ip.txt'         #ip address or range of microsoft CIDR notation
alexa_list_filepath = '/opt/alexalist.txt'                   #alexa top 1M list (without the first line of csv file)
alexa_exception_list_filepath = '/opt/alexa_exception.txt'   #some domain that we want to exclude from alexa list
md5_list_filepath = '/opt/md5.txt'                           #MD5 of known "safe" file
sha1_list_filepath = '/opt/sha1.txt'                         #SHA1 of known "safe" file
sha256_list_filepath = '/opt/sha256.txt'                     #SHA256 of known "safe" file
