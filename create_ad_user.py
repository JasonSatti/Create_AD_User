#!/usr/bin/env python3
# Jason Satti

import re

from ldap3 import Server, Connection, ALL


def set_ad_server_info():
    """Set the Active Directory Domain server information"""

    # Set domain server
    server = Server('ldaps://hostname.dc.dc', port=636, use_ssl=True,
                    get_info=ALL)

    # Set DC
    dc = 'cn=Users,dc=hostname,dc=dc,dc=dc'

    # Set domain user info
    domain_user = 'cn=domain.user' + ',' + dc
    password = 'password'

    return server, domain_user, password, dc


def get_ad_user_info(dc):
    """Prompt for new AD user information"""

    # Request new AD user information
    employee_full_name = input('What is the new employee\'s name? (format '
                               'First Last): ')
    employee_manager_name = input(
        'Who is the new employee\'s manager? (format '
        'First Last): ').lower()
    employee_title = input('What is the new employee\'s job title? ').title()
    employee_department = input('What is the new employee\'s department? '
                                '').title()
    employee_manager = 'cn=' + employee_manager_name.replace(' ', '.') + ',' \
                                                                         '' + dc
    employee_name = employee_full_name.split(' ')
    employee_first_name = employee_name[0]
    employee_last_name = employee_name[1]
    employee_first_adname = re.sub('\W', '', employee_first_name.lower())
    employee_last_adname = re.sub('\W', '', employee_last_name.lower())
    employee_full_adname = employee_first_adname + '.' + employee_last_adname
    employee_email = employee_full_adname + '@company.com'
    new_employee = 'cn=' + employee_full_adname + ',' + dc

    # Set up new ad user attributes
    attrs = {
        "objectClass": ['user', 'organizationalPerson', 'person', 'top'],
        "givenname": employee_first_name,
        "sn": employee_last_name,
        "cn": employee_full_adname,
        "displayName": employee_full_name,
        "samaccountname": employee_full_adname,
        "userprincipalname": employee_full_adname,
        "mail": employee_email,
        "manager": employee_manager,
        "title": employee_title,
        "department": employee_department
    }

    return new_employee, attrs, employee_full_adname


def main():
    """Connect to AD domain and create new user entry"""

    # Set up connector
    server, domain_user, password, dc = set_ad_server_info()
    ldap_connector = lambda: Connection(server, domain_user, password,
                                        return_empty_attributes=True,
                                        auto_bind=True)

    # Open a connection
    conn = ldap_connector()

    # Add new ad user
    new_employee, attrs, employee_full_adname = get_ad_user_info(dc)
    if not conn.search(dc, '(&(objectCategory=person)'
    F'(sAMAccountName={employee_full_adname}))'):
        conn.add(new_employee, attributes=attrs)
    else:
        print('Employee already exists in Active Directory')

    # Update user password
    conn.extend.microsoft.modify_password(new_employee, 'new.user1')

    # Enable new ad user account
    conn.modify(new_employee,
                {'userAccountControl': [('MODIFY_REPLACE', 512)]})


if __name__ == '__main__':
    main()
