#!/usr/bin/env python

from ad_client import ADClient
from ad_analysis import GroupTransitivityAnalysis

from collections import OrderedDict
import argparse
import sys
import csv
import json
from os import makedirs
import os.path as path
import math

from enum import IntFlag
class UAC(IntFlag):
    # https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx
    logonscript_executed = 0x1
    account_disabled = 0x2
    homedir_req = 0x8
    locked = 0x10
    passwd_not_reqd = 0x20
    passwd_cant_change = 0x40
    encrypted_txt_pw_allowd = 0x80
    duplicate_account = 0x100
    normal_account = 0x200
    interdomain_trust = 0x800
    workstation_dom = 0x1000
    dc_backup = 0x2000
    pw_dont_expire = 0x10000
    mns_logon = 0x20000
    smartcard_req = 0x40000
    trusted_for_delegation = 0x80000
    not_delegated = 0x100000
    des_only = 0x200000
    preauth_not_required = 0x400000
    pw_expired = 0x800000
    trusted_to_auth_for_delegation = 0x1000000


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

    @staticmethod
    def _get_kerberos_supported_types(bitflag):
        pass

    def get_computers(self):
        search_filter = '(objectCategory=Computer)'
        response = self.ad.query(search_filter)

        for entry in response:
            if entry.get('dn'):
                attributes = entry.get('attributes')
                #[print(k,v) for k,v in attributes.items()]
                #print()
                #print()
                #exit()
                yield OrderedDict([
                    ('DN', entry.get('dn')),
                    ('name', attributes.get('name')),
                    ('whenCreated', str(attributes.get('whenCreated'))),
                    ('OS_version', attributes.get('operatingSystemVersion')),
                    ('OS_name', attributes.get('operatingSystem')),
                    ('OS_servicepack', attributes.get('operatingSystemServicePack') or ''),
                    ('userAccountControl', attributes.get('userAccountControl') or ''),
                    ('fqdn', attributes.get('dNSHostName')),
                    ('spn', ', '.join(attributes.get('servicePrincipalName') or [])),

                    ('Login', '*'*10),
                    ('lastLogon', str(attributes.get('lastLogonTimestamp'))),
                    ('logonCount', attributes.get('logonCount')),

                    ('UAC', '*'*10),
                    ('UAC', (str(UAC(attributes.get('userAccountControl')
                                     or 0x0)).replace('UAC.', ''))),

                    ('Groups & SPN', '*'*10),
                    ('member_of', ', '.join(strip_and_sort_member_of(attributes.get('memberOf')) or [])),
                    ('Kerberos', recon._get_kerberos_supported_types(attributes.get('msDS-SupportedEncryptionTypes')))
                ])

    def get_users(self):
        search_filter = '(objectCategory=User)'
        response = self.ad.query(search_filter)

        for entry in response:
            if entry.get('dn'):
                attributes = entry.get('attributes')
                #[print(k,v) for k,v in attributes.items()]
                #print()
                #print()
                #exit(-1)
                yield OrderedDict([
                    ('DN', entry.get('dn')),

                    ('Account Details', '*'*10),
                    ('name', attributes.get('name')),
                    ('displayName', attributes.get('displayName')),
                    ('whenCreated', str(attributes.get('whenCreated'))),
                    ('SAMaccountName', attributes.get('sAMAccountName')),
                    ('cn', attributes.get('cn')),
                    ('upn', attributes.get('userPrincipalName')),
                    ('SID', attributes.get('objectSid')),

                    ('Pwd & failed auth', '*'*10),
                    ('pwdLastSet', str(attributes.get('pwdLastSet'))),
                    ('badPwdCount', attributes.get('badPwdCount')),
                    ('badPwdTime', str(attributes.get('badPasswordTime'))),

                    ('Login', '*'*10),
                    ('lastLogoff', str(attributes.get('lastLogoff'))),
                    ('lastLogon', str(attributes.get('lastLogon'))),
                    ('logonCount', attributes.get('logonCount')),

                    ('UAC', '*'*10),
                    ('UAC', (str(UAC(attributes.get('userAccountControl')
                                     or 0x0)).replace('UAC.', ''))),

                    ('Groups & SPN', '*'*10),
                    ('member_of', ', '.join(strip_and_sort_member_of(attributes.get('memberOf')) or [])),
                    ('spn', ', '.join(attributes.get('servicePrincipalName') or []))
                ])

    def get_policies(self):
        search_filter = '(objectClass=domain)'
        response = self.ad.query(search_filter)

        # Most policies are stored as number of intervals of 100 ns representing expiration period
        get_time_in_sec = lambda x: abs(x) * 100 * math.pow(10, -9)

        for entry in response:
            if entry.get('dn'):
                attributes = entry.get('attributes')
                #[print(k,v) for k,v in attributes.items()]
                #print()
                #print()
                #exit(-1)
                yield OrderedDict([
                    ('DN', entry.get('dn')),

                    #('lockoutThreshold (h)', get_time_in_sec(attributes.get('lockoutThreshold')) / 3600),

                    ('maxPwdAge (d)', get_time_in_sec(attributes.get('maxPwdAge')) / 3600 / 24),
                    ('lockOutObservationWindow (h)', get_time_in_sec(attributes.get('lockOutObservationWindow')) / 3600),
                    ('lockoutDuration (h)', get_time_in_sec(attributes.get('lockoutDuration')) / 3600),
                    ('lockoutThreshold (Faild Auth #)', attributes.get('lockoutThreshold')),

                    ('minPwdLength', attributes.get('minPwdLength')),
                    ('minPwdAge (d)', get_time_in_sec(attributes.get('minPwdAge') / 3600 / 24 )),
                    ('maxPwdAge (d)', get_time_in_sec(attributes.get('maxPwdAge') / 3600 / 24)),
                    ('msDS-Behavior-Version (DFS)', attributes.get('msDS-Behavior-Version'))
                ])

    def get_groups(self):
        search_filter = '(objectClass=Group)'
        response = self.ad.query(search_filter)

        print('Here!')

        for entry in response:
            if entry.get('dn'):
                attributes = entry.get('attributes')
                #[print(k,v) for k,v in attributes.items()]
                #print()
                #print()
                #exit(-1)
                yield OrderedDict([
                    ('DN', entry.get('dn')),

                    ('Group Details', ' '),
                    ('name', attributes.get('name')),
                    ('description', ','.join(attributes.get('description')) if type(attributes.get('description')) is list else (attributes.get('description') or '-')),
                    ('whenCreated', str(attributes.get('whenCreated'))),
                    ('SAMaccountName', attributes.get('sAMAccountName')),
                    ('cn', attributes.get('cn')),
                    ('SID', attributes.get('objectSid')),
                    ('adminCount', attributes.get('adminCount') or '-'),

                    ('Groups & SPN', '*'*10),
                    ('member_of', ', '.join(strip_and_sort_member_of(attributes.get('memberOf')) or []))
                ])
        pass


def strip_and_sort_member_of(member_of):
    if member_of:
        raw = [x.split(',') for x in member_of]
        groups = [x for dn in raw
                  for x in dn
                  if 'CN=Users' not in x and 'DC=' not in x and 'CN=Builtin' not in x]
        parsed = [x.split('=')[1] for x in groups if
                         len(x.split('=')) >1]
        parsed = list(set(parsed))
        parsed.sort()
        return parsed
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
        if v is None or not len(str(v)):
            v = "-"
        print('{: <20} {}'.format(k + ':', str(v)))


def dict_list_to_json(d, json_name):
    with open(path.join(args.out_dir, json_name), 'w', encoding='utf-8') as f:
        f.write(json.dumps(d))

def dict_list_to_csv(d, csv_name):
    with open(path.join(args.out_dir, csv_name), 'w', encoding='utf-8') as f:
        out_csv = csv.DictWriter(f, d[0].keys(), delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        out_csv.writeheader()
        out_csv.writerows(d)

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

    policies = [{'Policy':k, 'Value':v} for k,v in policies[0].items()]
    dict_list_to_json(policies, 'policy.json')
    dict_list_to_csv(policies, 'policy.csv')

    print('Getting computers...be patient...')
    computers = []
    for computer in recon.get_computers():
        computers += [computer]
        print_dict(computer)
        print()

    print('Saving computers...')
    dict_list_to_json(computers, 'computers.json')
    dict_list_to_csv(computers, 'computers.csv')

    print()

    print('Getting users...be patient...')
    users = []
    for user in recon.get_users():
        users += [user]
        print_dict(user)
        print()

    print('Saving users...')
    dict_list_to_json(users, 'user.json')

    print('Getting groups...be patient...')
    groups = []
    for group in recon.get_groups():
        groups += [group]
        print_dict(group)
        print()

    print('Saving groups...')
    dict_list_to_json(groups, 'group.json')
    dict_list_to_csv(groups, 'group.csv')

    print('Generating user-by-group list...be patient...')
    user_groups = {}
    for user in users:
        for group in user['member_of'].split(','):
            user_groups.setdefault(group.strip(), set()).update([user['SAMaccountName']])

    for k,v in user_groups.items():
        user_groups[k] = ','.join([x for x in v if x])

    print_dict(user_groups)
    print()

    # Gotta 'rotate' the dict to print it properly
    print('Saving user-groups...')
    user_groups = [{'Group':k, 'Users':v} for k,v in user_groups.items()]
    dict_list_to_json(user_groups, 'groups_user.json')
    dict_list_to_csv(user_groups, 'groups_user.csv')

    print("Getting all users in administrative groups")
    group_transitivity_analysis = GroupTransitivityAnalysis()

    da_list = []
    for da in group_transitivity_analysis.get_all_transitive_admins(users=users, groups=groups):
        da_list += [da]
        print_dict(da)
        print()

    print('Saving ad users...')
    dict_list_to_json(da_list, 'transitive_domain_admins.json')
    dict_list_to_csv(da_list, 'transitive_domain_admins.csv')
