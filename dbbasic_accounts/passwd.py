"""
User and authentication management mirroring Unix /etc/passwd, /etc/shadow, /etc/group
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from .tsv_db import Database


@dataclass
class User:
    """User object mirroring Unix user structure"""
    username: str
    uid: int
    gid: int
    fullname: str
    homedir: str
    shell: str
    created: str


class PasswdDB:
    """
    Unix-style user and authentication management using TSV files.

    Mirrors:
    - /etc/passwd → passwd.tsv
    - /etc/shadow → shadow.tsv
    - /etc/group → group.tsv
    """

    def __init__(self, etc_dir: str = "./etc"):
        """
        Initialize PasswdDB with directory for passwd/shadow/group files.

        Args:
            etc_dir: Directory to store passwd.tsv, shadow.tsv, group.tsv (like /etc)
        """
        self.etc_dir = Path(etc_dir)
        self.etc_dir.mkdir(parents=True, exist_ok=True)

        self.passwd_path = self.etc_dir / "passwd.tsv"
        self.shadow_path = self.etc_dir / "shadow.tsv"
        self.group_path = self.etc_dir / "group.tsv"

        # Initialize databases
        self._init_passwd()
        self._init_shadow()
        self._init_group()

        # Password hasher (Argon2id)
        self.ph = PasswordHasher()

    def _init_passwd(self):
        """Initialize passwd.tsv (like /etc/passwd)"""
        if not self.passwd_path.exists():
            self.passwd_path.write_text("username\tuid\tgid\tfullname\thomedir\tshell\tcreated\n")
        self.passwd_db = Database(str(self.passwd_path))

    def _init_shadow(self):
        """Initialize shadow.tsv (like /etc/shadow) - restricted permissions"""
        if not self.shadow_path.exists():
            self.shadow_path.write_text("username\tpassword_hash\tlast_changed\tmin_age\tmax_age\twarn_age\tinactive\n")
            # Set restricted permissions (like /etc/shadow)
            try:
                os.chmod(self.shadow_path, 0o600)
            except:
                pass  # May fail on Windows
        self.shadow_db = Database(str(self.shadow_path))

    def _init_group(self):
        """Initialize group.tsv (like /etc/group)"""
        if not self.group_path.exists():
            # Create default 'users' group
            self.group_path.write_text("groupname\tgid\tmembers\nusers\t100\t\n")
        self.group_db = Database(str(self.group_path))

    def _next_uid(self) -> int:
        """Get next available UID (starting at 1000 like Linux)"""
        users = self.passwd_db.select()
        if not users:
            return 1000
        return max(int(u['uid']) for u in users) + 1

    def _next_gid(self) -> int:
        """Get next available GID (starting at 100)"""
        groups = self.group_db.select()
        if not groups:
            return 100
        return max(int(g['gid']) for g in groups) + 1

    def useradd(
        self,
        username: str,
        password: str,
        fullname: str = "",
        homedir: Optional[str] = None,
        shell: str = "/bin/bash",
        gid: Optional[int] = None,
        groups: Optional[List[str]] = None
    ) -> User:
        """
        Add a new user (like Unix useradd).

        Args:
            username: Username (unique)
            password: Plain text password (will be hashed)
            fullname: Full name (like GECOS field)
            homedir: Home directory (defaults to /home/{username})
            shell: Login shell (defaults to /bin/bash)
            gid: Primary group ID (defaults to 'users' group)
            groups: Additional groups to add user to

        Returns:
            User object

        Raises:
            ValueError: If username already exists
        """
        # Check if user exists
        existing = self.passwd_db.select(where={'username': username})
        if existing:
            raise ValueError(f"User '{username}' already exists")

        # Get next UID
        uid = self._next_uid()

        # Get or create primary group
        if gid is None:
            users_group = self.group_db.select(where={'groupname': 'users'})
            if users_group:
                gid = int(users_group[0]['gid'])
            else:
                gid = 100
                self.group_db.insert({'groupname': 'users', 'gid': str(gid), 'members': ''})

        # Set homedir
        if homedir is None:
            homedir = f"/home/{username}"

        # Current timestamp
        now = datetime.now().isoformat()

        # Add to passwd
        self.passwd_db.insert({
            'username': username,
            'uid': str(uid),
            'gid': str(gid),
            'fullname': fullname,
            'homedir': homedir,
            'shell': shell,
            'created': now
        })

        # Hash password and add to shadow
        password_hash = self.ph.hash(password)
        self.shadow_db.insert({
            'username': username,
            'password_hash': password_hash,
            'last_changed': now,
            'min_age': '0',
            'max_age': '90',
            'warn_age': '7',
            'inactive': '14'
        })

        # Add to additional groups
        if groups:
            for group in groups:
                self.usermod(username, add_groups=[group])

        return User(
            username=username,
            uid=uid,
            gid=gid,
            fullname=fullname,
            homedir=homedir,
            shell=shell,
            created=now
        )

    def getuser(self, username: str) -> Optional[User]:
        """
        Get user by username.

        Args:
            username: Username to look up

        Returns:
            User object or None if not found
        """
        users = self.passwd_db.select(where={'username': username})
        if not users:
            return None

        u = users[0]
        return User(
            username=u['username'],
            uid=int(u['uid']),
            gid=int(u['gid']),
            fullname=u['fullname'],
            homedir=u['homedir'],
            shell=u['shell'],
            created=u['created']
        )

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user with password.

        Args:
            username: Username
            password: Plain text password

        Returns:
            User object if authentication succeeds, None otherwise
        """
        # Get user
        user = self.getuser(username)
        if not user:
            return None

        # Get password hash from shadow
        shadow_entry = self.shadow_db.select(where={'username': username})
        if not shadow_entry:
            return None

        password_hash = shadow_entry[0]['password_hash']

        # Verify password
        try:
            self.ph.verify(password_hash, password)

            # Check if rehash needed (Argon2 params changed)
            if self.ph.check_needs_rehash(password_hash):
                self.passwd_user(username, password)

            return user
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return None

    def passwd(self, username: str, new_password: str) -> bool:
        """
        Change user password (like Unix passwd).

        Args:
            username: Username
            new_password: New plain text password

        Returns:
            True if password changed, False if user not found
        """
        return self.passwd_user(username, new_password)

    def passwd_user(self, username: str, new_password: str) -> bool:
        """
        Change user password (alias for passwd).

        Args:
            username: Username
            new_password: New plain text password

        Returns:
            True if password changed, False if user not found
        """
        # Check user exists
        if not self.getuser(username):
            return False

        # Hash new password
        password_hash = self.ph.hash(new_password)
        now = datetime.now().isoformat()

        # Update shadow entry
        self.shadow_db.update(
            where={'username': username},
            values={'password_hash': password_hash, 'last_changed': now}
        )

        return True

    def usermod(
        self,
        username: str,
        fullname: Optional[str] = None,
        homedir: Optional[str] = None,
        shell: Optional[str] = None,
        add_groups: Optional[List[str]] = None,
        remove_groups: Optional[List[str]] = None
    ) -> bool:
        """
        Modify user (like Unix usermod).

        Args:
            username: Username to modify
            fullname: New full name
            homedir: New home directory
            shell: New shell
            add_groups: Groups to add user to
            remove_groups: Groups to remove user from

        Returns:
            True if user modified, False if user not found
        """
        # Check user exists
        if not self.getuser(username):
            return False

        # Update passwd fields
        updates = {}
        if fullname is not None:
            updates['fullname'] = fullname
        if homedir is not None:
            updates['homedir'] = homedir
        if shell is not None:
            updates['shell'] = shell

        if updates:
            self.passwd_db.update(where={'username': username}, values=updates)

        # Update group memberships
        if add_groups:
            for groupname in add_groups:
                self._add_user_to_group(username, groupname)

        if remove_groups:
            for groupname in remove_groups:
                self._remove_user_from_group(username, groupname)

        return True

    def userdel(self, username: str) -> bool:
        """
        Delete user (like Unix userdel).

        Args:
            username: Username to delete

        Returns:
            True if user deleted, False if user not found
        """
        # Check user exists
        if not self.getuser(username):
            return False

        # Remove from passwd
        self.passwd_db.delete(where={'username': username})

        # Remove from shadow
        self.shadow_db.delete(where={'username': username})

        # Remove from all groups
        all_groups = self.group_db.select()
        for group in all_groups:
            self._remove_user_from_group(username, group['groupname'])

        return True

    def groups(self, username: str) -> List[str]:
        """
        Get groups for user (like Unix groups command).

        Args:
            username: Username

        Returns:
            List of group names
        """
        user = self.getuser(username)
        if not user:
            return []

        group_list = []
        all_groups = self.group_db.select()

        for group in all_groups:
            # Check if user's primary group
            if int(group['gid']) == user.gid:
                group_list.append(group['groupname'])
            # Check if user in members
            elif username in group['members'].split(','):
                group_list.append(group['groupname'])

        return group_list

    def groupadd(self, groupname: str, gid: Optional[int] = None) -> Dict[str, Any]:
        """
        Add a new group (like Unix groupadd).

        Args:
            groupname: Group name
            gid: Group ID (auto-assigned if not provided)

        Returns:
            Dict with groupname, gid, members

        Raises:
            ValueError: If group already exists
        """
        # Check if group exists
        existing = self.group_db.select(where={'groupname': groupname})
        if existing:
            raise ValueError(f"Group '{groupname}' already exists")

        # Get next GID if not provided
        if gid is None:
            gid = self._next_gid()

        # Add group
        self.group_db.insert({
            'groupname': groupname,
            'gid': str(gid),
            'members': ''
        })

        return {'groupname': groupname, 'gid': gid, 'members': []}

    def _add_user_to_group(self, username: str, groupname: str):
        """Add user to group (internal helper)"""
        # Get or create group
        groups = self.group_db.select(where={'groupname': groupname})
        if not groups:
            self.groupadd(groupname)
            groups = self.group_db.select(where={'groupname': groupname})

        group = groups[0]
        members = [m for m in group['members'].split(',') if m]

        if username not in members:
            members.append(username)
            self.group_db.update(
                where={'groupname': groupname},
                values={'members': ','.join(members)}
            )

    def _remove_user_from_group(self, username: str, groupname: str):
        """Remove user from group (internal helper)"""
        groups = self.group_db.select(where={'groupname': groupname})
        if not groups:
            return

        group = groups[0]
        members = [m for m in group['members'].split(',') if m and m != username]

        self.group_db.update(
            where={'groupname': groupname},
            values={'members': ','.join(members)}
        )

    def list_users(self) -> List[User]:
        """
        List all users.

        Returns:
            List of User objects
        """
        users = []
        for u in self.passwd_db.select():
            users.append(User(
                username=u['username'],
                uid=int(u['uid']),
                gid=int(u['gid']),
                fullname=u['fullname'],
                homedir=u['homedir'],
                shell=u['shell'],
                created=u['created']
            ))
        return users

    def list_groups(self) -> List[Dict[str, Any]]:
        """
        List all groups.

        Returns:
            List of dicts with groupname, gid, members
        """
        groups = []
        for g in self.group_db.select():
            members = [m for m in g['members'].split(',') if m]
            groups.append({
                'groupname': g['groupname'],
                'gid': int(g['gid']),
                'members': members
            })
        return groups
