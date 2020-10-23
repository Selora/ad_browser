#!/usr/bin/env python

import argparse
import sys
import getpass

import ldap3
from ldap3 import Connection, Server, ALL, NTLM, ALL_ATTRIBUTES


class ADClient:
    """Wrapper around raw ldap mechanisms"""

    def __init__(self, ldap_server, windows_domain, username, password=None, ntlm=None, use_ssl=True):
        """Connect to the LDAP server credentials for username and password.
        Returns None on success or a string describing the error on failure
        # Adapt to your needs
        """
        self.use_ssl = use_ssl

        if self.use_ssl:
            self.server = Server(ldap_server, get_info=ALL, port=636, use_ssl=True)
        else:
            self.server = Server(ldap_server, get_info=ALL)

        try:
            if password:
                self._ldap_client = Connection(self.server, user=windows_domain + '\\' + username, password=password, auto_bind=True)
            elif ntlm:
                self._ldap_client = Connection(self.server, user=windows_domain + '\\' + username, password=ntlm, authentication=NTLM, auto_bind=True)
            else:
                password = getpass.getpass(prompt="Password for {}\\{}: ".format(windows_domain, username))
                self._ldap_client = Connection(self.server, user=windows_domain + '\\' + username, password=password, auto_bind=True)
        except ldap3.core.exceptions.LDAPBindError as e:
            print(e)
            exit(-1)
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            print(e)
            exit(-1)

    def __del__(self):
        if self.__dict__.get('_ldap_client'):
            self._ldap_client.unbind()

    def query(self, search_filter):
        results = self._paged_query(search_filter)
        return results
        #base_dn = ','.join(['dc=' + x for x in self.fqdn.split('.')])
        #return self._ldap_client.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)

    def _paged_query(self, search_filter, page_size = 10):
        """
        Behaves exactly like LDAPObject.search_ext_s() but internally uses the
        simple paged results control to retrieve search results in chunks.

        This is non-sense for really large results sets which you would like
        to process one-by-one
        """
        self._ldap_client.page_size = page_size
        base_dn = ','.join(self.server.info.other['defaultNamingContext'])
        entries = self._ldap_client.extend.standard.paged_search(base_dn,
                                                                 search_filter,
                                                                 attributes=ALL_ATTRIBUTES,
                                                                 paged_size=5)

        return entries


def parse_args(args):
    arg_parser = argparse.ArgumentParser(
        description='recon using ad ldap connector')

    arg_parser.add_argument('ldap_server',
                            type=str,
                            help='ldap server (ip or fqdn)')

    arg_parser.add_argument('windows_domain',
                            type=str,
                            default='',
                            help='ad domain netbios name (ex. enterprise.company.local would be ENTERPRISE)')

    arg_parser.add_argument('username',
                            type=str,
                            default='',
                            help='ad user, just the username!')

    group = arg_parser.add_mutually_exclusive_group()
    group.add_argument('--password', '-p',
                            type=str,
                            default=None,
                            help='user password.')
    group.add_argument('--ntlm_hash', '-H',
                       type=str,
                       default=None,
                       help='lm:ntlm hash. set lm to 000....00 if none')

    arg_parser.add_argument('--query','-q',
                            type=str,
                            default='(objectclass=*)',
                            help='query to perform (ldap filter format)')

    return arg_parser.parse_args(args)

test_args = [
    # Not up to date
    '--server_ip', '192.168.56.100',
    '--username', 'Administrator',
    '--password', 'redlabpw1!',
    '--query', '(&(objectClass=*)(servicePrincipalName=*))'
]

if __name__ == "__main__":

    args = parse_args(sys.argv[1:])

    if len(sys.argv) == 1:
        args = parse_args(test_args)

    adclient = ADClient(ldap_server=args.ldap_server,
                        windows_domain=args.windows_domain,
                        username=args.username,
                        password=args.password,
                        ntlm=args.ntlm_hash)

    [print(x) for x in adclient.query(args.query)]
