#!/usr/bin/env python
"""
Example usage of dbbasic-accounts - Web-Friendly API
"""

from dbbasic_accounts import Accounts

# Initialize (creates ./etc/, ./home/, ./var/mail/ directories)
accounts = Accounts('.', domain='example.com')

print("=== Web-Friendly API Example ===\n")

# Register a user (web-style, with email)
user = accounts.register('john@example.com', 'secret123', name='John Doe')
print(f"✓ Registered user: {user.username} (UID {user.uid})")
print(f"  Email: john@example.com")
print(f"  Fullname: {user.fullname}")

# Login (authenticate with email)
authenticated_user = accounts.login('john@example.com', 'secret123')
if authenticated_user:
    print(f"✓ Login successful for {authenticated_user.username}")
else:
    print("✗ Login failed")

# Add roles (groups)
accounts.add_role('john@example.com', 'editor')
accounts.add_role('john@example.com', 'admin')
print(f"✓ Added roles: editor, admin")

# Check user roles
roles = accounts.get_roles('john@example.com')
print(f"  Roles for john@example.com: {roles}")

# Get user by different methods
user_by_email = accounts.get_user(email='john@example.com')
user_by_id = accounts.get_user(user_id=1000)
user_by_username = accounts.get_user(username='john')
print(f"✓ Retrieved user by email, ID, and username")

# Get filesystem paths
home_dir = accounts.get_home_directory('john@example.com')
mailbox = accounts.get_mailbox('john@example.com')
print(f"  Home directory: {home_dir}")
print(f"  Mailbox: {mailbox}")

# Change password
accounts.change_password('john@example.com', 'newsecret456')
print(f"✓ Password changed")

# Register another user
user2 = accounts.register('jane@example.com', 'pass123', name='Jane Smith')
print(f"\n✓ Registered user: {user2.username} (UID {user2.uid})")

# List all users
print("\n=== All Users ===")
for user in accounts.list_users():
    print(f"  {user.username}: {user.fullname} (UID {user.uid})")

print("\n=== File Structure ===")
print("Check these directories:")
print("  ./etc/passwd.tsv   - User database")
print("  ./etc/shadow.tsv   - Password hashes")
print("  ./etc/group.tsv    - Groups/roles")
print("  ./home/john/       - John's home directory")
print("  ./home/jane/       - Jane's home directory")
print("  ./var/mail/john    - John's mailbox")
print("  ./var/mail/jane    - Jane's mailbox")

print("\n=== Unix Commands Work! ===")
print("Try these commands:")
print("  cat etc/passwd.tsv")
print("  ls home/john/")
print("  cat var/mail/john")
