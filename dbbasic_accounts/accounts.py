"""
Web-friendly accounts API built on top of Unix-style PasswdDB
"""

import os
from pathlib import Path
from typing import Optional
from .passwd import PasswdDB, User


class Accounts:
    """
    Web-friendly accounts management with filesystem integration.

    Built on top of Unix PasswdDB, adds:
    - Email-based registration/login
    - Home directory creation
    - Mailbox creation
    - Convenience methods for web apps
    """

    def __init__(self, base_dir: str = ".", domain: str = "localhost"):
        """
        Initialize Accounts system.

        Args:
            base_dir: Base directory for the Unix-style filesystem
            domain: Default domain for email addresses
        """
        self.base_dir = Path(base_dir)
        self.domain = domain

        # Initialize directory structure
        self.etc_dir = self.base_dir / "etc"
        self.home_dir = self.base_dir / "home"
        self.var_dir = self.base_dir / "var"
        self.mail_dir = self.var_dir / "mail"

        # Create directories
        self.etc_dir.mkdir(parents=True, exist_ok=True)
        self.home_dir.mkdir(parents=True, exist_ok=True)
        self.var_dir.mkdir(parents=True, exist_ok=True)
        self.mail_dir.mkdir(parents=True, exist_ok=True)

        # Initialize PasswdDB (Unix layer)
        self.passwd = PasswdDB(str(self.etc_dir))

    def _email_to_username(self, email: str) -> str:
        """Extract username from email (john@example.com -> john)"""
        return email.split('@')[0]

    def _create_home_directory(self, username: str) -> Path:
        """Create home directory for user"""
        user_home = self.home_dir / username
        user_home.mkdir(parents=True, exist_ok=True)

        # Create common subdirectories
        (user_home / "uploads").mkdir(exist_ok=True)

        return user_home

    def _create_mailbox(self, username: str) -> Path:
        """Create mailbox file for user"""
        mailbox = self.mail_dir / username
        if not mailbox.exists():
            mailbox.touch()
        return mailbox

    def register(self, email: str, password: str, name: str = '') -> User:
        """
        Register new user (web-friendly).

        Args:
            email: Email address (becomes username@domain)
            password: Plain text password (will be hashed)
            name: Display name

        Returns:
            User object

        Raises:
            ValueError: If user already exists

        Example:
            user = accounts.register('john@example.com', 'secret123', name='John Doe')
            # Creates:
            # - etc/passwd.tsv: john entry
            # - etc/shadow.tsv: john password
            # - etc/group.tsv: adds john to users group
            # - home/john/ directory
            # - var/mail/john mailbox
        """
        username = self._email_to_username(email)

        # Build fullname with email
        fullname = f"{name} <{email}>" if name else email

        # Create user in passwd database
        user = self.passwd.useradd(
            username=username,
            password=password,
            fullname=fullname,
            homedir=f"/home/{username}"
        )

        # Create filesystem structures
        self._create_home_directory(username)
        self._create_mailbox(username)

        return user

    def login(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate user (web-friendly).

        Args:
            email: Email address
            password: Plain text password

        Returns:
            User object if valid, None otherwise

        Example:
            user = accounts.login('john@example.com', 'secret123')
            if user:
                session['user_id'] = user.uid
                session['username'] = user.username
        """
        username = self._email_to_username(email)
        return self.passwd.authenticate(username, password)

    def get_user(self, user_id: Optional[int] = None,
                 email: Optional[str] = None,
                 username: Optional[str] = None) -> Optional[User]:
        """
        Get user by ID, email, or username.

        Args:
            user_id: User ID (uid)
            email: Email address
            username: Username

        Returns:
            User object or None

        Example:
            user = accounts.get_user(user_id=1000)
            user = accounts.get_user(email='john@example.com')
            user = accounts.get_user(username='john')
        """
        if username:
            return self.passwd.getuser(username)

        if email:
            username = self._email_to_username(email)
            return self.passwd.getuser(username)

        if user_id is not None:
            # Search by UID
            for user in self.passwd.list_users():
                if user.uid == user_id:
                    return user

        return None

    def add_role(self, email: str, role: str) -> bool:
        """
        Add role to user (convenience method for groups).

        Args:
            email: Email address
            role: Role name (becomes group)

        Returns:
            True if added, False if user not found

        Example:
            accounts.add_role('john@example.com', 'editor')
        """
        username = self._email_to_username(email)
        return self.passwd.usermod(username, add_groups=[role])

    def remove_role(self, email: str, role: str) -> bool:
        """
        Remove role from user.

        Args:
            email: Email address
            role: Role name (group)

        Returns:
            True if removed, False if user not found
        """
        username = self._email_to_username(email)
        return self.passwd.usermod(username, remove_groups=[role])

    def get_roles(self, email: str) -> list[str]:
        """
        Get roles for user (groups).

        Args:
            email: Email address

        Returns:
            List of role names

        Example:
            roles = accounts.get_roles('john@example.com')
            # ['users', 'editors', 'admins']
        """
        username = self._email_to_username(email)
        return self.passwd.groups(username)

    def change_password(self, email: str, new_password: str) -> bool:
        """
        Change user password.

        Args:
            email: Email address
            new_password: New plain text password

        Returns:
            True if changed, False if user not found
        """
        username = self._email_to_username(email)
        return self.passwd.passwd(username, new_password)

    def delete_user(self, email: str) -> bool:
        """
        Delete user account.

        Args:
            email: Email address

        Returns:
            True if deleted, False if user not found
        """
        username = self._email_to_username(email)
        return self.passwd.userdel(username)

    def list_users(self) -> list[User]:
        """
        List all users.

        Returns:
            List of User objects
        """
        return self.passwd.list_users()

    def get_home_directory(self, email: str) -> Optional[Path]:
        """
        Get path to user's home directory.

        Args:
            email: Email address

        Returns:
            Path to home directory or None if user not found
        """
        username = self._email_to_username(email)
        user = self.passwd.getuser(username)
        if not user:
            return None
        return self.home_dir / username

    def get_mailbox(self, email: str) -> Optional[Path]:
        """
        Get path to user's mailbox.

        Args:
            email: Email address

        Returns:
            Path to mailbox file or None if user not found
        """
        username = self._email_to_username(email)
        user = self.passwd.getuser(username)
        if not user:
            return None
        return self.mail_dir / username
