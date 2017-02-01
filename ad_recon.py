#!/usr/bin/env python

from ad_client import ADClient

from collections import OrderedDict
import argparse
import sys
import csv
from os import makedirs
import os.path as path


def stringify(x):
    """To extract LDAP value as readable and exportable"""
    if x:
        return ','.join([y.decode('utf-8') for y in x])
    else:
        return ''


class ADRecon:
    """Use the ad_client to perform various steps of recon"""

    def __init__(self, ad_client):
        self.ad = ad_client

    def get_computers(self):
        search_filter = '(objectCategory=Computer)'
        response = self.ad.query(search_filter)

        for entry in response:
            if entry.get('dn'):
                attributes = entry.get('attributes')
                yield OrderedDict([
                    ('DN', entry.get('dn')),
                    ('name', attributes.get('name')),
                    ('OS_version', attributes.get('operatingSystemVersion')),
                    ('OS_name', attributes.get('operatingSystem')),
                    ('OS_servicepack', attributes.get('operatingSystemServicePack') or ''),
                    ('fqdn', attributes.get('dNSHostName')),
                    ('spn', ', '.join(attributes.get('servicePrincipalName')))
                ])

    def get_users(self):
        search_filter = '(objectCategory=User)'
        response = self.ad.query(search_filter)

        for entry in response:
            if entry.get('dn'):
                attributes = entry.get('attributes')
                #[print(k,v) for k,v in attributes.items()]
                yield OrderedDict([
                    ('DN', entry.get('dn')),

                    ('name', attributes.get('name')),
                    ('SAMaccountName', attributes.get('sAMAccountName')),
                    ('cn', attributes.get('cn')),
                    ('upn', attributes.get('userPrincipalName')),

                    ('SID', attributes.get('objectSid')),
                    ('pwdLastSet', attributes.get('pwdLastSet')),

                    ('member_of', ', '.join(strip_member_of(attributes.get('memberOf')) or [])),

                    ('spn', ', '.join(attributes.get('servicePrincipalName') or []))
                ])

    def get_policies(self):
        search_filter = '(objectClass=domain)'
        response = self.ad.query(search_filter)

        for entry in response:
            if entry.get('dn'):
                attributes = entry.get('attributes')
                yield OrderedDict([
                    ('DN', entry.get('dn')),

                    ('lockoutThreshold', attributes.get('lockoutThreshold')),
                    ('maxPwdAge', attributes.get('maxPwdAge')),
                    ('lockOutObservationWindow', attributes.get('lockOutObservationWindow')),
                    ('lockoutDuration', attributes.get('lockoutDuration')),
                    ('lockoutThreshold', attributes.get('lockoutThreshold')),

                    ('minPwdLength', attributes.get('minPwdLength')),
                    ('minPwdAge', attributes.get('minPwdAge')),
                    ('maxPwdAge', attributes.get('maxPwdAge')),
                    ('msDS-Behavior-Version (DFS)', attributes.get('msDS-Behavior-Version'))
                ])

def strip_member_of(member_of):
    if member_of:
        raw = [x.split(',') for x in member_of]
        groups = [x for group in raw for x in group
                  if 'Users' not in x and 'DC' not in x and 'Builtin' not in x]
        return [x.split('=')[1] for x in groups if
                         len(x.split('=')) >1]
    else:
        return []


def parse_args(args):
    arg_parser = argparse.ArgumentParser(
        description='Recon using AD ldap connector')

    arg_parser.add_argument('ldap_server',
                            type=str,
                            help='ldap server (ip or fqdn)')

    arg_parser.add_argument('windows_domain',
                            type=str,
                            default='',
                            help='ad domain netbios name (ex. enterprise.company.local would be enterprise)')

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
                       help='lm:ntlm')

    arg_parser.add_argument('--out_dir', '-o',
                            type=str,
                            default='ldap_recon',
                            help='Directory to output csv data')

    return arg_parser.parse_args(args)

test_args = [
    '--server_ip', '192.168.56.100',
    '--fqdn', 'redlab.com',
    '--username', 'win7',
    '--password', 'redlabpw1!',
    '--grp', 'Admin',
    '--spn', 'LDAP'
]

def print_dict(d):
    # Compute longest key for pretty print
    for k,v in d.items():
        print('{: <20} {}'.format(k + ':', str(v)))


def dict_list_to_csv(d, csv_name):
    with open(path.join(args.out_dir, csv_name), 'w') as f:
        out_csv = csv.DictWriter(f, d[0].keys())
        out_csv.writeheader()
        out_csv.writerows(d)

def dict_to_csv(d, headers, csv_name):
    with open(path.join(args.out_dir, csv_name), 'w') as f:
        out_csv = csv.writer(f)
        out_csv.writerow(headers)
        for k,v in d.items():
            out_csv.writerow([k, v])


if __name__ == "__main__":

    args = parse_args(sys.argv[1:])

    # if len(sys.argv) == 1:
    #     args = parse_args(test_args)

    adclient = ADClient(ldap_server=args.ldap_server,
                        windows_domain=args.windows_domain,
                        username=args.username,
                        password=args.password,
                        ntlm=args.ntlm_hash)

    makedirs(args.out_dir, exist_ok=True)
    with open(path.join(args.out_dir, 'smartcard'),'w') as f:
        # Todo
        if None and args.smartcard:
            print('SmartCart:')
            uac_smartcard_filter = '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=262144))'
            response = adclient.query(uac_smartcard_filter)
            for x in response:
                print(x[0])
                print(x[1])
                f.write(str(x[0]))
                f.write(str(x[1]))

    recon = ADRecon(adclient)

    print('Getting policy...')
    policies = [policy for policy in recon.get_policies()]

    for policy in policies:
        print_dict(policy)
    print()

    dict_list_to_csv(policies, 'policy.csv')

    print('Getting computers...be patient...')
    computers = [computer for computer in recon.get_computers()]
    dict_list_to_csv(computers, 'computers.csv')

    for x in computers:
        print_dict(x)
        print()

    print()

    print('Getting users...be patient...')
    users = [user for user in recon.get_users()]

    for x in users:
        print_dict(x)
        print()

    dict_list_to_csv(users, 'user.csv')

    print('Generating user-by-group list...be patient...')
    groups = {}
    for user in users:
        for group in user['member_of'].split(','):
            groups.setdefault(group.strip(), set()).update([user['SAMaccountName']])

    for k,v in groups.items():
        groups[k] = ','.join([x for x in v if x])

    print_dict(groups)
    print()

    dict_to_csv(groups, ['group', 'users'], 'groups.csv')
