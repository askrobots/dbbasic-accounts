"""Users management admin interface"""

from dbbasic_accounts import Accounts


def handle(request):
    """
    Handle /admin/accounts/users requests.

    Lists all users with their roles, status, and last login.
    """
    # Initialize accounts system
    accounts = Accounts()

    # Get all users
    users = accounts.list_users()

    # Build user data for display
    user_data = []
    for user in users:
        # Extract email from fullname (format: "Name <email>" or just "email")
        email = user.fullname
        if '<' in email and '>' in email:
            email = email.split('<')[1].split('>')[0]

        # Get user's roles (groups)
        roles = accounts.get_roles(email)

        # Determine primary role for badge
        primary_role = 'User'
        badge_class = 'badge-green'
        if 'admin' in roles or 'admins' in roles:
            primary_role = 'Admin'
            badge_class = 'badge-red'
        elif 'editor' in roles or 'editors' in roles:
            primary_role = 'Editor'
            badge_class = 'badge-blue'

        # Get initials for avatar
        name_parts = user.fullname.split('<')[0].strip().split()
        initials = ''.join([p[0].upper() for p in name_parts[:2]]) if name_parts else user.username[:2].upper()

        user_data.append({
            'id': user.uid,
            'username': user.username,
            'email': email,
            'fullname': user.fullname.split('<')[0].strip() or user.username,
            'initials': initials,
            'role': primary_role,
            'badge_class': badge_class,
            'status': 'Active',  # TODO: track last login
            'status_class': 'status-active',
            'last_login': '—',  # TODO: implement last login tracking
        })

    # Build HTML
    from dbbasic_admin.admin import build_nav
    nav_items = build_nav()
    nav_html = "".join(f'<li><a href="{item["href"]}">{item.get("icon", "")} {item["label"]}</a></li>' for item in nav_items)

    # Build users table rows
    users_html = ""
    for u in user_data:
        users_html += f"""
        <tr>
            <td><input type="checkbox"></td>
            <td>
                <div class="user-cell">
                    <div class="user-avatar">{u['initials']}</div>
                    <span class="user-name">{u['fullname']}</span>
                </div>
            </td>
            <td>{u['email']}</td>
            <td><span class="badge {u['badge_class']}">{u['role']}</span></td>
            <td>{u['last_login']}</td>
            <td><span class="status-dot {u['status_class']}"></span> {u['status']}</td>
            <td>
                <div class="action-buttons">
                    <button class="btn-icon" title="Edit">✏️</button>
                    <button class="btn-icon" title="Delete">🗑️</button>
                </div>
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Users - Admin</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; height: 100vh; background: #f5f5f5; }}
        .sidebar {{ width: 250px; background: #2c3e50; color: white; padding: 20px; overflow-y: auto; }}
        .sidebar h1 {{ font-size: 24px; margin-bottom: 30px; color: #ecf0f1; }}
        .sidebar ul {{ list-style: none; }}
        .sidebar li {{ margin-bottom: 10px; }}
        .sidebar a {{ color: #ecf0f1; text-decoration: none; display: block; padding: 10px; border-radius: 5px; transition: background 0.2s; }}
        .sidebar a:hover, .sidebar a.active {{ background: #34495e; }}
        .content {{ flex: 1; padding: 40px; overflow-y: auto; }}
        .header {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .header h2 {{ color: #2c3e50; margin: 0; }}
        .btn-primary {{ background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; }}
        .btn-primary:hover {{ background: #2980b9; }}
        .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .table-container {{ overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .user-cell {{ display: flex; align-items: center; gap: 10px; }}
        .user-avatar {{ width: 40px; height: 40px; border-radius: 50%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 14px; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
        .badge-red {{ background: #fee; color: #c00; }}
        .badge-blue {{ background: #e3f2fd; color: #1976d2; }}
        .badge-green {{ background: #e8f5e9; color: #388e3c; }}
        .status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }}
        .status-active {{ background: #4caf50; }}
        .status-inactive {{ background: #999; }}
        .action-buttons {{ display: flex; gap: 5px; }}
        .btn-icon {{ background: none; border: none; cursor: pointer; font-size: 16px; padding: 5px; }}
        .btn-icon:hover {{ opacity: 0.7; }}
        .breadcrumb {{ color: #666; font-size: 14px; }}
        .filters-card {{ background: white; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .filters-row {{ display: flex; gap: 10px; align-items: center; }}
        .search-input {{ flex: 1; padding: 8px 12px; border: 1px solid #ddd; border-radius: 5px; }}
        .filter-select {{ padding: 8px 12px; border: 1px solid #ddd; border-radius: 5px; background: white; }}
        .btn-secondary {{ background: #6c757d; color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="sidebar"><h1>Admin</h1><ul>{nav_html}</ul></div>
    <div class="content">
        <div class="header">
            <div>
                <h2>Users</h2>
                <div class="breadcrumb">Home / Users</div>
            </div>
            <button class="btn-primary">+ New User</button>
        </div>

        <div class="filters-card">
            <div class="filters-row">
                <input type="search" placeholder="Search users..." class="search-input">
                <select class="filter-select">
                    <option>All Roles</option>
                    <option>Admin</option>
                    <option>Editor</option>
                    <option>Author</option>
                </select>
                <select class="filter-select">
                    <option>All Status</option>
                    <option>Active</option>
                    <option>Inactive</option>
                </select>
                <button class="btn-secondary">Filter</button>
            </div>
        </div>

        <div class="card">
            <h3 style="margin-bottom: 20px;">All Users ({len(user_data)})</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th><input type="checkbox"></th>
                            <th>User</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Last Login</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>"""

    # Return HTML response using dbbasic_web format
    try:
        from dbbasic_web.responses import html as html_response
        return html_response(html_content)
    except ImportError:
        # Fallback if dbbasic_web not available
        return (200, [('content-type', 'text/html; charset=utf-8')], [html_content.encode()])
