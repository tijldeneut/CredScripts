#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2020, Photubias <tijl.deneut@howest.be>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
'''
Decrypting Stored Passwords in WinSCP, the data can be found in the registry at this location:
HKCU\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions\
Or: NTUSER.DAT in SOFTWARE\Martin Prikryl\WinSCP 2\Sessions\
'''
import optparse

def decryptWinSCP(hexPassword,sHostname, sUsername):
    def decrypt(bData): return ~(bData ^ 0xA3)%256 ## MAGIC BYTE
    bPassword = bytes.fromhex(hexPassword)
    if decrypt(bPassword[0]) == 0xFF: ## New Version
        bPassword = bPassword[1:] 
        iLen = decrypt(bPassword[1])
    else: ## Older Version
        iLen = decrypt(bPassword[0]) 
    iOffset = decrypt(bPassword[2])
    bPassword = bPassword[3+iOffset:]
    sResult = ''
    for bChar in bPassword:
        sResult += chr(decrypt(bChar))
    sResult = sResult[:iLen] ## only the first characters are useful
    ## Result at this point is HOSTNAME+USERNAME+PASSWORD
    if not sHostname == '' and not sUsername == '' and sUsername.lower() + sHostname.lower() in sResult.lower():
        return sResult[len(sHostname) + len(sUsername):]
    else:
        return sResult
        
if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options]\n\n'
        'Decrypting credentials from WinSCP (2) Registry\n'
        'The required data can be found at\n'
        'HKCU\\SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions\\')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--host', metavar='STRING', dest='hostname', default='', help='Optional')
    parser.add_option('--user', metavar='STRING', dest='username', default='', help='Optional')
    parser.add_option('--pass', metavar='HEX', dest='password')

    (options, args) = parser.parse_args()

    if not options.password: exit('[-] Error: no HEX password found')
    sResult = decryptWinSCP(options.password,options.hostname,options.username)
    print('[+] Succes!')
    if options.hostname == '' or options.username == '':
        print('[!] Warning, you did not provide username/hostname so this is the full decrypted string')
    print('     ' + sResult)
