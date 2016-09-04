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

misp_url = 'https://mispserver.local'
misp_key = 'FGHGFHGFHGFHGFHGFHGFHGF' # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True # True if you have a valid cert on your server
