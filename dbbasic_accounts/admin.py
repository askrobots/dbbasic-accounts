"""
Admin interface configuration for dbbasic-accounts

This module is auto-discovered by dbbasic-admin
"""

# Navigation configuration
ADMIN_CONFIG = [
    {
        'icon': '👥',
        'label': 'Users',
        'href': '/admin/accounts/users',
        'order': 30  # After Code (10) and Database (11)
    }
]
