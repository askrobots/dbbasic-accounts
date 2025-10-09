#!/usr/bin/env python
"""
Complete Flask app with dbbasic-passwd authentication

Replaces Flask-Login + SQLAlchemy with simple TSV files.
"""

from flask import Flask, request, session, redirect, url_for, render_template_string
from functools import wraps
from dbbasic_passwd import PasswdDB

app = Flask(__name__)
app.secret_key = 'change-this-in-production'  # Use secrets.token_hex(16) in production

# Initialize auth database
passwd = PasswdDB('./etc')

# Create demo users if database is empty
if not passwd.list_users():
    passwd.useradd('admin', password='admin123', fullname='Admin User', groups=['admins'])
    passwd.useradd('editor', password='editor123', fullname='Editor User', groups=['editors'])
    passwd.useradd('user', password='user123', fullname='Regular User')
    print("Created demo users: admin/admin123, editor/editor123, user/user123")


# Auth decorators
def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Require user to be in 'admins' group"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))

        groups = passwd.groups(session['username'])
        if 'admins' not in groups:
            return 'Forbidden: Admin access required', 403

        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """Get current logged-in user"""
    if 'username' in session:
        return passwd.getuser(session['username'])
    return None


# Routes
@app.route('/')
def index():
    user = get_current_user()
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>dbbasic-passwd Flask Demo</title>
            <style>
                body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                .user-info { background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .links { margin-top: 20px; }
                .links a { display: inline-block; margin-right: 15px; padding: 10px 15px;
                          background: #007bff; color: white; text-decoration: none; border-radius: 3px; }
                .links a:hover { background: #0056b3; }
                .logout { background: #dc3545 !important; }
                .logout:hover { background: #c82333 !important; }
            </style>
        </head>
        <body>
            <h1>dbbasic-passwd Flask Demo</h1>

            {% if user %}
                <div class="user-info">
                    <h2>Logged in as {{ user.fullname }}</h2>
                    <p><strong>Username:</strong> {{ user.username }}</p>
                    <p><strong>UID:</strong> {{ user.uid }}</p>
                    <p><strong>Groups:</strong> {{ groups|join(', ') }}</p>
                </div>

                <div class="links">
                    <a href="{{ url_for('dashboard') }}">Dashboard</a>
                    <a href="{{ url_for('profile') }}">Profile</a>
                    {% if 'admins' in groups %}
                        <a href="{{ url_for('admin') }}">Admin Panel</a>
                    {% endif %}
                    <a href="{{ url_for('logout') }}" class="logout">Logout</a>
                </div>
            {% else %}
                <p>Welcome! Please <a href="{{ url_for('login') }}">login</a> to continue.</p>

                <h3>Demo accounts:</h3>
                <ul>
                    <li><strong>admin</strong> / admin123 (has admin access)</li>
                    <li><strong>editor</strong> / editor123 (has editor access)</li>
                    <li><strong>user</strong> / user123 (regular user)</li>
                </ul>
            {% endif %}
        </body>
        </html>
    ''', user=user, groups=passwd.groups(user.username) if user else [])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Authenticate with dbbasic-passwd
        user = passwd.authenticate(username, password)

        if user:
            # Login successful - store in session
            session['username'] = user.username
            session['uid'] = user.uid
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password'
            return render_template_string(LOGIN_TEMPLATE, error=error)

    return render_template_string(LOGIN_TEMPLATE, error=None)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    groups = passwd.groups(user.username)

    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <style>
                body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                .card { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <h1>Dashboard</h1>

            <div class="card">
                <h2>Welcome, {{ user.fullname }}!</h2>
                <p>This is your dashboard. Only logged-in users can see this page.</p>
                <p><strong>Your groups:</strong> {{ groups|join(', ') }}</p>
            </div>

            <p><a href="{{ url_for('index') }}">← Back to home</a></p>
        </body>
        </html>
    ''', user=user, groups=groups)


@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    groups = passwd.groups(user.username)

    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Profile</title>
            <style>
                body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                table { width: 100%; border-collapse: collapse; }
                td { padding: 10px; border-bottom: 1px solid #ddd; }
                td:first-child { font-weight: bold; width: 200px; }
            </style>
        </head>
        <body>
            <h1>User Profile</h1>

            <table>
                <tr><td>Username</td><td>{{ user.username }}</td></tr>
                <tr><td>Full Name</td><td>{{ user.fullname }}</td></tr>
                <tr><td>UID</td><td>{{ user.uid }}</td></tr>
                <tr><td>GID</td><td>{{ user.gid }}</td></tr>
                <tr><td>Home Directory</td><td>{{ user.homedir }}</td></tr>
                <tr><td>Shell</td><td>{{ user.shell }}</td></tr>
                <tr><td>Groups</td><td>{{ groups|join(', ') }}</td></tr>
                <tr><td>Created</td><td>{{ user.created }}</td></tr>
            </table>

            <p><a href="{{ url_for('change_password') }}">Change Password</a></p>
            <p><a href="{{ url_for('index') }}">← Back to home</a></p>
        </body>
        </html>
    ''', user=user, groups=groups)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = get_current_user()

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Verify current password
        if not passwd.authenticate(user.username, current_password):
            error = 'Current password is incorrect'
        elif new_password != confirm_password:
            error = 'New passwords do not match'
        elif len(new_password) < 6:
            error = 'Password must be at least 6 characters'
        else:
            # Change password
            passwd.passwd(user.username, new_password)
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head><title>Password Changed</title></head>
                <body style="font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px;">
                    <h1>Password Changed</h1>
                    <p>Your password has been changed successfully.</p>
                    <p><a href="{{ url_for('profile') }}">← Back to profile</a></p>
                </body>
                </html>
            ''')

        return render_template_string(CHANGE_PASSWORD_TEMPLATE, error=error)

    return render_template_string(CHANGE_PASSWORD_TEMPLATE, error=None)


@app.route('/admin')
@admin_required
def admin():
    users = passwd.list_users()
    groups = passwd.list_groups()

    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel</title>
            <style>
                body { font-family: sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; }
                table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
                th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
                th { background: #007bff; color: white; }
                .danger { background: #dc3545; color: white; padding: 5px 10px;
                         text-decoration: none; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>Admin Panel</h1>
            <p><em>Only users in 'admins' group can access this page.</em></p>

            <h2>Users</h2>
            <table>
                <tr>
                    <th>Username</th>
                    <th>Full Name</th>
                    <th>UID</th>
                    <th>Groups</th>
                    <th>Created</th>
                </tr>
                {% for user in users %}
                <tr>
                    <td>{{ user.username }}</td>
                    <td>{{ user.fullname }}</td>
                    <td>{{ user.uid }}</td>
                    <td>{{ user_groups[user.username]|join(', ') }}</td>
                    <td>{{ user.created }}</td>
                </tr>
                {% endfor %}
            </table>

            <h2>Groups</h2>
            <table>
                <tr>
                    <th>Group Name</th>
                    <th>GID</th>
                    <th>Members</th>
                </tr>
                {% for group in groups %}
                <tr>
                    <td>{{ group.groupname }}</td>
                    <td>{{ group.gid }}</td>
                    <td>{{ group.members|join(', ') if group.members else '(empty)' }}</td>
                </tr>
                {% endfor %}
            </table>

            <p><a href="{{ url_for('index') }}">← Back to home</a></p>
        </body>
        </html>
    ''', users=users, groups=groups,
         user_groups={u.username: passwd.groups(u.username) for u in users})


# HTML Templates
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        form { background: #f8f9fa; padding: 30px; border-radius: 5px; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white;
                border: none; border-radius: 3px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .error { color: #dc3545; padding: 10px; background: #f8d7da; border-radius: 3px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <h1>Login</h1>

    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}

    <form method="POST">
        <input type="text" name="username" placeholder="Username" required autofocus>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>

    <p style="text-align: center; margin-top: 20px;">
        <a href="{{ url_for('index') }}">← Back to home</a>
    </p>
</body>
</html>
'''

CHANGE_PASSWORD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Change Password</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        form { background: #f8f9fa; padding: 30px; border-radius: 5px; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white;
                border: none; border-radius: 3px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .error { color: #dc3545; padding: 10px; background: #f8d7da; border-radius: 3px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <h1>Change Password</h1>

    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}

    <form method="POST">
        <input type="password" name="current_password" placeholder="Current Password" required autofocus>
        <input type="password" name="new_password" placeholder="New Password" required>
        <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
        <button type="submit">Change Password</button>
    </form>

    <p style="text-align: center; margin-top: 20px;">
        <a href="{{ url_for('profile') }}">← Cancel</a>
    </p>
</body>
</html>
'''


if __name__ == '__main__':
    print("\n" + "="*60)
    print("Flask app with dbbasic-passwd authentication")
    print("="*60)
    print("\nDemo users:")
    print("  - admin/admin123 (has admin access)")
    print("  - editor/editor123 (has editor access)")
    print("  - user/user123 (regular user)")
    print("\nRunning on http://127.0.0.1:5000")
    print("="*60 + "\n")

    app.run(debug=True, port=5000)
