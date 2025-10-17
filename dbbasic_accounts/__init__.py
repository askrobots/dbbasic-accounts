"""
dbbasic-accounts: Unix-style user accounts with web-friendly API

Dual API design:
- PasswdDB: Unix layer (useradd, passwd, groups commands)
- Accounts: Web layer (register, login, email-based)

Both use the same underlying TSV files (passwd.tsv, shadow.tsv, group.tsv).
"""

from .passwd import PasswdDB, User
from .accounts import Accounts

__version__ = "0.1.1"
__all__ = ["Accounts", "PasswdDB", "User"]
