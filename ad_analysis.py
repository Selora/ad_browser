from collections import OrderedDict

class BaseAnalysis:
    """
    Represent a basic analysis.
    """
    def __init__(self):
        pass

class SPNAnalysis(BaseAnalysis):
    """Get all SPNs from computers/users/groups"""

    def get_mssql_server_as_user_account(self):
        """
        Return all MSSQL User SPN (User account running MSSQL. If there's any, dump TGS with impacket!)
        """
        pass


    def get_mssql_servers(self):
        """
        Return all MSSQL computer SPNs (Windows server running MSSQL.)
        """
        pass

    def get_exchange_servers(self):
        """
        Return all MS Exchanges computer SPNs (Use sensepost ruleR!)
        """
        pass


class GroupTransitivityAnalysis(BaseAnalysis):
    """Get all group memberships of users/computer accounts"""

    def get_all_transitive_admins(self, users, groups):
        """
        Return a list of all user/computer accounts that are in administrative group (think DCsync)
        """
        for user in users:
            found_groups = [x for x in groups if x.get('SAMaccountName') in user.get('member_of').split(', ')]
            admin_groups = [x for x in found_groups if x.get('adminCount') != '-']
            if admin_groups:
                yield OrderedDict([
                    ('User', user.get('SAMaccountName')),
                    ('Admin Groups', ', '.join([x.get('SAMaccountName') for x in  admin_groups]))
                ])

        pass

    def get_all_users_in_groups(self, groups:list):
        """
        Return all users in groups taking account transitivity
        """
        pass

class ADTrustAnalysis(BaseAnalysis):
    """Get all domain trust and relationships"""

    def get_trusted_accounts(self):
        """
        Return accounts in trusted groups
        """
        pass
