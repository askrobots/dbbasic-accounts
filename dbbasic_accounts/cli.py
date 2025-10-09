"""
Command-line interface for dbbasic-accounts

Mirrors Unix commands: useradd, usermod, userdel, passwd, groups
"""

import sys
import getpass
from pathlib import Path
from argparse import ArgumentParser

from .passwd import PasswdDB


def main():
    """Main CLI entry point"""
    parser = ArgumentParser(
        description='Unix-style user accounts with web-friendly API',
        prog='dbaccounts'
    )
    parser.add_argument(
        '--etc-dir',
        default='./etc',
        help='Directory for passwd/shadow/group files (default: ./etc)'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # init command
    init_parser = subparsers.add_parser('init', help='Initialize database')

    # useradd command
    useradd_parser = subparsers.add_parser('useradd', help='Add a new user')
    useradd_parser.add_argument('username', help='Username')
    useradd_parser.add_argument('--fullname', default='', help='Full name')
    useradd_parser.add_argument('--homedir', help='Home directory')
    useradd_parser.add_argument('--shell', default='/bin/bash', help='Shell')
    useradd_parser.add_argument('--groups', help='Comma-separated list of groups')
    useradd_parser.add_argument('--password', help='Password (prompts if not provided)')

    # usermod command
    usermod_parser = subparsers.add_parser('usermod', help='Modify a user')
    usermod_parser.add_argument('username', help='Username')
    usermod_parser.add_argument('--fullname', help='New full name')
    usermod_parser.add_argument('--homedir', help='New home directory')
    usermod_parser.add_argument('--shell', help='New shell')
    usermod_parser.add_argument('--add-groups', help='Comma-separated groups to add')
    usermod_parser.add_argument('--remove-groups', help='Comma-separated groups to remove')

    # userdel command
    userdel_parser = subparsers.add_parser('userdel', help='Delete a user')
    userdel_parser.add_argument('username', help='Username')

    # passwd command
    passwd_parser = subparsers.add_parser('passwd', help='Change password')
    passwd_parser.add_argument('username', help='Username')
    passwd_parser.add_argument('--password', help='New password (prompts if not provided)')

    # groups command
    groups_parser = subparsers.add_parser('groups', help='Show user groups')
    groups_parser.add_argument('username', help='Username')

    # groupadd command
    groupadd_parser = subparsers.add_parser('groupadd', help='Add a new group')
    groupadd_parser.add_argument('groupname', help='Group name')
    groupadd_parser.add_argument('--gid', type=int, help='Group ID')

    # list command
    list_parser = subparsers.add_parser('list', help='List users or groups')
    list_parser.add_argument(
        'type',
        nargs='?',
        default='users',
        choices=['users', 'groups'],
        help='Type to list (default: users)'
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize PasswdDB
    passwd = PasswdDB(etc_dir=args.etc_dir)

    # Handle commands
    if args.command == 'init':
        print(f"Initialized database in {args.etc_dir}/")
        print(f"  - {args.etc_dir}/passwd.tsv")
        print(f"  - {args.etc_dir}/shadow.tsv")
        print(f"  - {args.etc_dir}/group.tsv")
        return 0

    elif args.command == 'useradd':
        # Get password
        if args.password:
            password = args.password
        else:
            password = getpass.getpass('Password: ')
            password2 = getpass.getpass('Confirm password: ')
            if password != password2:
                print("Passwords do not match", file=sys.stderr)
                return 1

        # Parse groups
        groups = None
        if args.groups:
            groups = [g.strip() for g in args.groups.split(',')]

        try:
            user = passwd.useradd(
                username=args.username,
                password=password,
                fullname=args.fullname,
                homedir=args.homedir,
                shell=args.shell,
                groups=groups
            )
            print(f"User '{user.username}' created (UID {user.uid})")
            return 0
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    elif args.command == 'usermod':
        # Parse groups
        add_groups = None
        remove_groups = None
        if args.add_groups:
            add_groups = [g.strip() for g in args.add_groups.split(',')]
        if args.remove_groups:
            remove_groups = [g.strip() for g in args.remove_groups.split(',')]

        result = passwd.usermod(
            username=args.username,
            fullname=args.fullname,
            homedir=args.homedir,
            shell=args.shell,
            add_groups=add_groups,
            remove_groups=remove_groups
        )

        if result:
            print(f"User '{args.username}' modified")
            return 0
        else:
            print(f"Error: User '{args.username}' not found", file=sys.stderr)
            return 1

    elif args.command == 'userdel':
        result = passwd.userdel(args.username)
        if result:
            print(f"User '{args.username}' deleted")
            return 0
        else:
            print(f"Error: User '{args.username}' not found", file=sys.stderr)
            return 1

    elif args.command == 'passwd':
        # Check user exists
        user = passwd.getuser(args.username)
        if not user:
            print(f"Error: User '{args.username}' not found", file=sys.stderr)
            return 1

        # Get password
        if args.password:
            new_password = args.password
        else:
            new_password = getpass.getpass('New password: ')
            new_password2 = getpass.getpass('Confirm password: ')
            if new_password != new_password2:
                print("Passwords do not match", file=sys.stderr)
                return 1

        passwd.passwd(args.username, new_password)
        print(f"Password for '{args.username}' changed")
        return 0

    elif args.command == 'groups':
        user = passwd.getuser(args.username)
        if not user:
            print(f"Error: User '{args.username}' not found", file=sys.stderr)
            return 1

        groups = passwd.groups(args.username)
        print(' '.join(groups))
        return 0

    elif args.command == 'groupadd':
        try:
            group = passwd.groupadd(args.groupname, gid=args.gid)
            print(f"Group '{group['groupname']}' created (GID {group['gid']})")
            return 0
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    elif args.command == 'list':
        if args.type == 'users':
            users = passwd.list_users()
            if not users:
                print("No users")
                return 0

            # Format like Unix passwd -a
            for user in users:
                print(f"{user.username}:x:{user.uid}:{user.gid}:{user.fullname}:{user.homedir}:{user.shell}")
        else:  # groups
            groups = passwd.list_groups()
            if not groups:
                print("No groups")
                return 0

            # Format like Unix /etc/group
            for group in groups:
                members = ','.join(group['members'])
                print(f"{group['groupname']}:x:{group['gid']}:{members}")

        return 0

    return 0


if __name__ == '__main__':
    sys.exit(main())
