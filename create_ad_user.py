#!/usr/bin/env python3
# Jason Satti
from ldap3 import Server, Connection, ALL


def set_ad_server_info():
    """Set the Active Directory Domain server information"""

    # Set domain server
    server = Server('ldaps://hostname.dc.dc', port=636, use_ssl=True,
                    get_info=ALL)

    # Set DC
    dc = ',cn=Users,dc=hostname,dc=dc,dc=dc'

    # Set domain user info
    domain_user = 'cn=domain.user' + dc
    password = 'password'

    return server, domain_user, password, dc


def get_ad_user_info(dc):
    """Prompt for new AD user information"""

    # Request new AD user information
    employee_full_name = input('What is the new employee\'s name? (format '
                               'first.last): ').lower()
    employee_manager_name = input(
        'Who is the new employee\'s manager? (format '
        'first.last): ').lower()
    employee_title = input('What is the new employee\'s job title? ').title()
    employee_department = input('What is the new employee\'s department? '
                                '').title()
    employee_manager = 'cn=' + employee_manager_name + dc
    employee_name = employee_full_name.split('.')
    employee_first_name = employee_name[0]
    employee_last_name = employee_name[1]
    employee_display_name = employee_first_name.capitalize() + " " + \
                            employee_last_name.capitalize()
    employee_email = employee_full_name + '@company.com'
    new_employee = 'cn=' + employee_full_name + dc

    # Set up new ad user attributes
    attrs = {
        "objectClass": ['user', 'organizationalPerson', 'person', 'top'],
        "givenname": employee_first_name,
        "sn": employee_last_name,
        "cn": employee_full_name,
        "displayName": employee_display_name,
        "samaccountname": employee_full_name,
        "mail": employee_email,
        "manager": employee_manager,
        "title": employee_title,
        "department": employee_department
    }

    return new_employee, attrs


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
    new_employee, attrs = get_ad_user_info(dc)
    conn.add(new_employee, attributes=attrs)

    # Update user password
    conn.extend.microsoft.modify_password(new_employee, 'new.user1')

    # Enable new ad user account
    conn.modify(new_employee,
                {'userAccountControl': [('MODIFY_REPLACE', 512)]})


if __name__ == '__main__':
    main()