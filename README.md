# dbbasic-accounts

[![PyPI version](https://badge.fury.io/py/dbbasic-accounts.svg)](https://badge.fury.io/py/dbbasic-accounts)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Unix-style user accounts with web-friendly API and filesystem integration.

> "The web forked from Unix. Let's merge it back."

## Why?

**The critical insight:** Unix already solved user management, authentication, and permissions. The web abandoned it and reinvented everything poorly. What if we just... used Unix?

Docker = isolated Unix system per app. Each container can have its own `/etc/passwd` without conflicts. **We can return to Unix.**

## Features

- **Dual API**: Unix layer (useradd, passwd) + Web layer (register, login)
- **Email-based auth**: Use emails like `john@example.com`
- **Filesystem integration**: Auto-creates home directories and mailboxes
- **Unix-compatible**: Commands like `cat etc/passwd.tsv` work
- **Zero dependencies**: Just Python and TSV files
- **Secure**: Argon2id password hashing

## Installation

```bash
pip install dbbasic-accounts
```

**PyPI**: [https://pypi.org/project/dbbasic-accounts/](https://pypi.org/project/dbbasic-accounts/)

**GitHub**: [https://github.com/askrobots/dbbasic-accounts](https://github.com/askrobots/dbbasic-accounts)

## Quick Start

### Web-Friendly API

```python
from dbbasic_accounts import Accounts

# Initialize (creates etc/, home/, var/ directories)
accounts = Accounts('.', domain='example.com')

# Register user (web-style)
user = accounts.register('john@example.com', 'secret', name='John Doe')
# Creates:
# - etc/passwd.tsv entry
# - etc/shadow.tsv password hash
# - home/john/ directory
# - var/mail/john mailbox

# Login (web-style)
user = accounts.login('john@example.com', 'secret')
if user:
    print(f"Welcome {user.fullname}!")

# Add roles
accounts.add_role('john@example.com', 'editor')
accounts.add_role('john@example.com', 'admin')

# Check roles
roles = accounts.get_roles('john@example.com')
print(roles)  # ['users', 'editor', 'admin']

# Get user
user = accounts.get_user(email='john@example.com')
user = accounts.get_user(user_id=1000)
user = accounts.get_user(username='john')
```

### Unix-Style API

```python
from dbbasic_accounts import PasswdDB

# Initialize
passwd = PasswdDB('./etc')

# Unix commands (just like the real thing)
user = passwd.useradd('john', password='secret', fullname='John Doe')
passwd.passwd('john', 'newsecret')
passwd.usermod('john', add_groups=['editors', 'admins'])
print(passwd.groups('john'))  # ['users', 'editors', 'admins']

# Authenticate
user = passwd.authenticate('john', 'newsecret')
if user:
    print(f"Authenticated: {user.username}")
```

## File Structure

Your app becomes a Unix system:

```
myapp/
├── etc/
│   ├── passwd.tsv      # Users (like /etc/passwd)
│   ├── shadow.tsv      # Password hashes (like /etc/shadow, mode 0600)
│   └── group.tsv       # Groups/roles (like /etc/group)
├── home/               # User directories
│   ├── john/           # User john's files
│   │   ├── profile.jpg
│   │   └── uploads/
│   └── jane/
├── var/
│   ├── mail/           # Email spool (user inboxes)
│   │   ├── john
│   │   └── jane
│   └── log/            # Logs
└── app.py              # Your web app
```

Now Unix tools work:

```bash
# List users
cat etc/passwd.tsv

# Check user's files
ls home/john/

# Read user's mailbox
cat var/mail/john
```

## API Reference

### Accounts Class (Web-Friendly)

#### register(email, password, name='')

Register new user.

```python
user = accounts.register('john@example.com', 'secret123', name='John Doe')
# Returns User object
# Creates home directory and mailbox
```

#### login(email, password)

Authenticate user.

```python
user = accounts.login('john@example.com', 'secret123')
if user:
    session['user_id'] = user.uid
    session['username'] = user.username
```

#### get_user(user_id=None, email=None, username=None)

Get user by ID, email, or username.

```python
user = accounts.get_user(user_id=1000)
user = accounts.get_user(email='john@example.com')
user = accounts.get_user(username='john')
```

#### add_role(email, role)

Add role to user (groups).

```python
accounts.add_role('john@example.com', 'editor')
```

#### get_roles(email)

Get user's roles.

```python
roles = accounts.get_roles('john@example.com')
# ['users', 'editors', 'admins']
```

#### change_password(email, new_password)

Change user password.

```python
accounts.change_password('john@example.com', 'newsecret')
```

#### delete_user(email)

Delete user account.

```python
accounts.delete_user('john@example.com')
```

#### get_home_directory(email)

Get path to user's home directory.

```python
home = accounts.get_home_directory('john@example.com')
# Path: home/john/
```

#### get_mailbox(email)

Get path to user's mailbox.

```python
mailbox = accounts.get_mailbox('john@example.com')
# Path: var/mail/john
```

### PasswdDB Class (Unix-Compatible)

Full Unix-style commands:

- `useradd(username, password, fullname, groups)` - Add user
- `getuser(username)` - Get user
- `authenticate(username, password)` - Auth user
- `passwd(username, new_password)` - Change password
- `usermod(username, add_groups, remove_groups)` - Modify user
- `userdel(username)` - Delete user
- `groups(username)` - Get user's groups
- `groupadd(groupname, gid)` - Add group
- `list_users()` - List all users
- `list_groups()` - List all groups

See [dbbasic-passwd](https://github.com/yourusername/dbbasic-passwd) for full Unix API docs.

## Flask Integration

```python
from flask import Flask, session, request, redirect, render_template
from dbbasic_accounts import Accounts

app = Flask(__name__)
app.secret_key = 'your-secret-key'
accounts = Accounts('./data', domain='example.com')

@app.route('/register', methods=['POST'])
def register():
    try:
        user = accounts.register(
            request.form['email'],
            request.form['password'],
            name=request.form['name']
        )
        session['user_id'] = user.uid
        session['email'] = request.form['email']
        return redirect('/dashboard')
    except ValueError as e:
        return str(e), 400

@app.route('/login', methods=['POST'])
def login():
    user = accounts.login(
        request.form['email'],
        request.form['password']
    )
    if user:
        session['user_id'] = user.uid
        session['email'] = request.form['email']
        return redirect('/dashboard')
    return 'Invalid credentials', 401

@app.route('/admin')
def admin():
    email = session.get('email')
    if not email:
        return redirect('/login')

    # Check if user has admin role
    if 'admin' not in accounts.get_roles(email):
        return 'Forbidden', 403

    return render_template('admin.html')

@app.route('/profile')
def profile():
    email = session.get('email')
    if not email:
        return redirect('/login')

    user = accounts.get_user(email=email)
    home_dir = accounts.get_home_directory(email)

    return render_template('profile.html', user=user, home_dir=home_dir)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
```

## Docker Integration

```dockerfile
FROM python:3.11

WORKDIR /app

# Install dbbasic-accounts
RUN pip install dbbasic-accounts

# Copy app
COPY app.py /app/

# Initialize users (optional - can also do this in app.py)
RUN python -c "
from dbbasic_accounts import Accounts
accounts = Accounts('/app/data', domain='example.com')
accounts.register('admin@example.com', 'changeme', name='Admin User')
accounts.add_role('admin@example.com', 'admin')
"

CMD ["python", "app.py"]
```

Each container = isolated Unix system with its own users. No conflicts.

## Design Philosophy

1. **Mirror Unix**: Use 50 years of battle-tested design
2. **Stay Compatible**: Unix commands should work
3. **Web-Friendly**: Add convenience for web developers
4. **No Fork**: Don't diverge from Unix, extend it
5. **Filesystem Integration**: home/ and var/mail/ like real Unix

## Comparison

### Traditional Web Apps

```python
# Requires MySQL server, complex schema, ORMs
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

user = User.objects.create_user('john', 'john@example.com', 'secret')
user = authenticate(username='john', password='secret')
```

### dbbasic-accounts

```python
# Just TSV files, no database
from dbbasic_accounts import Accounts

accounts = Accounts('.')
user = accounts.register('john@example.com', 'secret')
user = accounts.login('john@example.com', 'secret')
```

## TSV File Format

### passwd.tsv

```tsv
username	uid	gid	fullname	homedir	shell	created
john	1000	100	John Doe <john@example.com>	/home/john	/bin/bash	2025-10-09T10:30:00
jane	1001	100	Jane Smith <jane@example.com>	/home/jane	/bin/bash	2025-10-09T11:00:00
```

### shadow.tsv

```tsv
username	password_hash	last_changed	min_age	max_age	warn_age	inactive
john	$argon2id$v=19$m=65536,t=3,p=4$...	2025-10-09T10:30:00	0	90	7	14
jane	$argon2id$v=19$m=65536,t=3,p=4$...	2025-10-09T11:00:00	0	90	7	14
```

### group.tsv

```tsv
groupname	gid	members
users	100
editors	101	john,jane
admins	102	john
```

## Security

- **Argon2id**: Current best-practice password hashing (winner of Password Hashing Competition)
- **Automatic rehashing**: Passwords automatically rehashed if Argon2 parameters change
- **shadow.tsv permissions**: Automatically set to 0600 (owner read/write only) on Unix
- **No plaintext passwords**: Passwords never stored in plaintext

## Requirements

- Python 3.8+
- argon2-cffi >= 23.1.0

## Testing

```bash
pip install -e ".[dev]"
pytest
pytest --cov=dbbasic_accounts
```

## License

MIT

## Credits

Inspired by:
- Unix user management (`/etc/passwd`, `/etc/shadow`, `/etc/group`)
- Docker's container isolation
- The need to escape MySQL/ORM complexity

Part of the dbbasic-* family:
- [dbbasic-tsv](https://github.com/yourusername/dbbasic-tsv) - TSV database
- dbbasic-accounts - This package
