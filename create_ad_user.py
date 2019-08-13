#!/usr/bin/env python3
# Jason Satti

import argparse
import os
import re

from ldap3 import Server, Connection, ALL


def set_ad_server_info(ad_username, ad_password):
    """Set the Active Directory Domain server information.

    :param ad_username: Passed in via CLI or ad_info file
    :param ad_password: Passed in via CLI
    """

    # Set domain server
    server = Server("ldaps://hostname.dc.dc", port=636, use_ssl=True, get_info=ALL)

    # Set DC
    dc = "cn=Users,dc=hostname,dc=dc,dc=dc"

    # Set domain user info
    domain_user = f"cn={ad_username}" + "," + dc
    password = ad_password

    return server, domain_user, password, dc


def save_domain_username(username):
    """Save AD domain admin username to file.

    :param username: Passed in via CLI
    """

    username_template = f"""username='{username}'\n"""
    with os.fdopen(os.open("ad_info.py", os.O_WRONLY | os.O_CREAT, 0o600), "w") as F:
        F.write(username_template)


def get_ad_user_info(dc, temp):
    """Prompt for new AD user information.

    :param dc: Generated via set_ad_server_info() and passed in.
    """

    # Request new AD user information
    employee_full_name = input(
        "What is the new employee's name? (format " "First Last): "
    )
    employee_manager_name = input(
        "Who is the new employee's manager? (format " "First Last): "
    ).lower()
    employee_title = input("What is the new employee's job title? ").title()
    employee_department = input("What is the new employee's department? " "").title()

    # Parse new AD user information
    employee_manager = "cn=" + employee_manager_name.replace(" ", ".") + "," "" + dc
    employee_name = employee_full_name.split(" ")
    employee_first_name = employee_name[0]
    employee_last_name = employee_name[1]
    employee_first_adname = re.sub("\W", "", employee_first_name.lower())
    employee_last_adname = re.sub("\W", "", employee_last_name.lower())
    if temp is True:
        employee_full_adname = (
            employee_first_adname + "." + employee_last_adname + ".temp"
        )
    else:
        employee_full_adname = employee_first_adname + "." + employee_last_adname
    employee_email = employee_full_adname + "@addepar.com"
    new_employee = "cn=" + employee_full_adname + "," + dc

    # Set up new ad user attributes
    attrs = {
        "objectClass": ["user", "organizationalPerson", "person", "top"],
        "givenname": employee_first_name,
        "sn": employee_last_name,
        "cn": employee_full_adname,
        "displayName": employee_full_name,
        "samaccountname": employee_full_adname,
        "userprincipalname": employee_full_adname + "@addedc.addepar.com",
        "mail": employee_email,
        "manager": employee_manager,
        "title": employee_title,
        "department": employee_department,
    }

    return new_employee, attrs, employee_full_adname


def main():
    """Connect to AD domain and create new user entry."""

    # Get AD Domain user info via CLI
    parser = argparse.ArgumentParser(
        description="Set up AD domain admin " "information."
    )
    parser.add_argument(
        "-un",
        "--username",
        required=False,
        type=str,
        help="Username of AD domain admin in the format "
        "fist.last. Mandatory on first run, optional "
        "after if -ru/--remember flag is used.",
    )
    parser.add_argument(
        "-pw",
        "--password",
        required=True,
        type=str,
        help="Password of AD domain admin.",
    )
    parser.add_argument(
        "-tp",
        "--temp",
        action="store_true",
        default=False,
        help="Flag for temp worker setup.",
    )
    parser.add_argument(
        "-ru",
        "--remember",
        action="store_true",
        default=False,
        help="Save AD domain admin username locally.",
    )
    args = parser.parse_args()

    if args.remember is True:
        save_domain_username(args.username)

    if os.path.exists("./ad_info.py"):
        import ad_info

        args.username = ad_info.username

    # Set up connector
    server, domain_user, password, dc = set_ad_server_info(args.username, args.password)
    ldap_connector = lambda: Connection(
        server, domain_user, password, return_empty_attributes=True, auto_bind=True
    )

    # Open a connection
    conn = ldap_connector()

    # Get new ad user info
    new_employee, attrs, employee_full_adname = get_ad_user_info(dc, args.temp)

    # Check if ad user exists
    if not conn.search(
        dc, "(&(objectCategory=person)" f"(sAMAccountName={employee_full_adname}))"
    ):
        # Add new ad user
        conn.add(new_employee, attributes=attrs)
        # Set new ad user password
        conn.extend.microsoft.modify_password(new_employee, "new.user1")
        # Enable new ad user account
        conn.modify(new_employee, {"userAccountControl": [("MODIFY_REPLACE", 512)]})
        # Force password reset on next login
        conn.modify(new_employee, {"pwdLastSet": [("MODIFY_REPLACE", 0)]})
    else:
        print("Employee already exists in Active Directory")

    # Verify ad user account was created
    if conn.search(
        dc, "(&(objectCategory=person)" f"(sAMAccountName={employee_full_adname}))"
    ):
        print(f"{employee_full_adname} was successfully created in AD.")
    else:
        print(f"Error while creating {employee_full_adname} in AD.")


if __name__ == "__main__":
    main()
