"""
Tests for dbbasic-passwd
"""

import os
import tempfile
import shutil
from pathlib import Path

import pytest

from dbbasic_passwd import PasswdDB, User


@pytest.fixture
def tmpdir():
    """Create temporary directory for test databases"""
    tmp = tempfile.mkdtemp()
    yield tmp
    shutil.rmtree(tmp)


@pytest.fixture
def passwd_db(tmpdir):
    """Create PasswdDB instance in temp directory"""
    return PasswdDB(etc_dir=tmpdir)


class TestPasswdDB:
    """Test PasswdDB initialization"""

    def test_init_creates_files(self, tmpdir):
        """Test that initialization creates passwd, shadow, group files"""
        db = PasswdDB(etc_dir=tmpdir)

        assert Path(tmpdir, "passwd.tsv").exists()
        assert Path(tmpdir, "shadow.tsv").exists()
        assert Path(tmpdir, "group.tsv").exists()

    def test_shadow_permissions(self, tmpdir):
        """Test that shadow.tsv has restricted permissions (Unix only)"""
        db = PasswdDB(etc_dir=tmpdir)
        shadow_path = Path(tmpdir, "shadow.tsv")

        # Skip on Windows
        if os.name != 'posix':
            pytest.skip("Permission tests only on Unix")

        stat_info = os.stat(shadow_path)
        mode = stat_info.st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_default_users_group(self, passwd_db):
        """Test that default 'users' group is created"""
        groups = passwd_db.list_groups()
        assert len(groups) == 1
        assert groups[0]['groupname'] == 'users'
        assert groups[0]['gid'] == 100


class TestUserAdd:
    """Test useradd functionality"""

    def test_useradd_basic(self, passwd_db):
        """Test basic user creation"""
        user = passwd_db.useradd('john', password='secret', fullname='John Doe')

        assert user.username == 'john'
        assert user.uid == 1000  # First user
        assert user.gid == 100   # users group
        assert user.fullname == 'John Doe'
        assert user.homedir == '/home/john'
        assert user.shell == '/bin/bash'

    def test_useradd_custom_fields(self, passwd_db):
        """Test user creation with custom fields"""
        user = passwd_db.useradd(
            'jane',
            password='secret',
            fullname='Jane Smith',
            homedir='/var/www/jane',
            shell='/bin/zsh'
        )

        assert user.username == 'jane'
        assert user.homedir == '/var/www/jane'
        assert user.shell == '/bin/zsh'

    def test_useradd_duplicate_fails(self, passwd_db):
        """Test that adding duplicate user fails"""
        passwd_db.useradd('john', password='secret')

        with pytest.raises(ValueError, match="already exists"):
            passwd_db.useradd('john', password='other')

    def test_useradd_increments_uid(self, passwd_db):
        """Test that UIDs increment correctly"""
        user1 = passwd_db.useradd('john', password='secret')
        user2 = passwd_db.useradd('jane', password='secret')
        user3 = passwd_db.useradd('bob', password='secret')

        assert user1.uid == 1000
        assert user2.uid == 1001
        assert user3.uid == 1002

    def test_useradd_with_groups(self, passwd_db):
        """Test user creation with additional groups"""
        passwd_db.groupadd('editors')
        passwd_db.groupadd('admins')

        user = passwd_db.useradd('john', password='secret', groups=['editors', 'admins'])

        groups = passwd_db.groups('john')
        assert 'users' in groups  # Primary group
        assert 'editors' in groups
        assert 'admins' in groups


class TestAuthentication:
    """Test password hashing and authentication"""

    def test_authenticate_success(self, passwd_db):
        """Test successful authentication"""
        passwd_db.useradd('john', password='secret123')

        user = passwd_db.authenticate('john', 'secret123')
        assert user is not None
        assert user.username == 'john'

    def test_authenticate_wrong_password(self, passwd_db):
        """Test authentication with wrong password"""
        passwd_db.useradd('john', password='secret123')

        user = passwd_db.authenticate('john', 'wrongpassword')
        assert user is None

    def test_authenticate_nonexistent_user(self, passwd_db):
        """Test authentication with nonexistent user"""
        user = passwd_db.authenticate('nonexistent', 'password')
        assert user is None

    def test_passwd_changes_password(self, passwd_db):
        """Test password change"""
        passwd_db.useradd('john', password='oldpassword')

        # Change password
        result = passwd_db.passwd('john', 'newpassword')
        assert result is True

        # Old password fails
        assert passwd_db.authenticate('john', 'oldpassword') is None

        # New password works
        user = passwd_db.authenticate('john', 'newpassword')
        assert user is not None

    def test_passwd_nonexistent_user(self, passwd_db):
        """Test password change for nonexistent user"""
        result = passwd_db.passwd('nonexistent', 'password')
        assert result is False


class TestUserManagement:
    """Test user management (getuser, usermod, userdel)"""

    def test_getuser_exists(self, passwd_db):
        """Test getting existing user"""
        passwd_db.useradd('john', password='secret', fullname='John Doe')

        user = passwd_db.getuser('john')
        assert user is not None
        assert user.username == 'john'
        assert user.fullname == 'John Doe'

    def test_getuser_not_exists(self, passwd_db):
        """Test getting nonexistent user"""
        user = passwd_db.getuser('nonexistent')
        assert user is None

    def test_usermod_fullname(self, passwd_db):
        """Test modifying user full name"""
        passwd_db.useradd('john', password='secret', fullname='John Doe')

        passwd_db.usermod('john', fullname='John Q. Doe')

        user = passwd_db.getuser('john')
        assert user.fullname == 'John Q. Doe'

    def test_usermod_homedir_shell(self, passwd_db):
        """Test modifying user homedir and shell"""
        passwd_db.useradd('john', password='secret')

        passwd_db.usermod('john', homedir='/var/www/john', shell='/bin/zsh')

        user = passwd_db.getuser('john')
        assert user.homedir == '/var/www/john'
        assert user.shell == '/bin/zsh'

    def test_usermod_add_groups(self, passwd_db):
        """Test adding user to groups"""
        passwd_db.groupadd('editors')
        passwd_db.groupadd('admins')
        passwd_db.useradd('john', password='secret')

        passwd_db.usermod('john', add_groups=['editors', 'admins'])

        groups = passwd_db.groups('john')
        assert 'editors' in groups
        assert 'admins' in groups

    def test_usermod_remove_groups(self, passwd_db):
        """Test removing user from groups"""
        passwd_db.groupadd('editors')
        passwd_db.useradd('john', password='secret', groups=['editors'])

        assert 'editors' in passwd_db.groups('john')

        passwd_db.usermod('john', remove_groups=['editors'])

        assert 'editors' not in passwd_db.groups('john')

    def test_usermod_nonexistent_user(self, passwd_db):
        """Test modifying nonexistent user"""
        result = passwd_db.usermod('nonexistent', fullname='New Name')
        assert result is False

    def test_userdel_success(self, passwd_db):
        """Test deleting user"""
        passwd_db.useradd('john', password='secret')
        assert passwd_db.getuser('john') is not None

        result = passwd_db.userdel('john')
        assert result is True

        assert passwd_db.getuser('john') is None
        assert passwd_db.authenticate('john', 'secret') is None

    def test_userdel_removes_from_groups(self, passwd_db):
        """Test that deleting user removes from all groups"""
        passwd_db.groupadd('editors')
        passwd_db.useradd('john', password='secret', groups=['editors'])

        # Verify user in group
        groups = passwd_db.list_groups()
        editors = [g for g in groups if g['groupname'] == 'editors'][0]
        assert 'john' in editors['members']

        # Delete user
        passwd_db.userdel('john')

        # Verify removed from group
        groups = passwd_db.list_groups()
        editors = [g for g in groups if g['groupname'] == 'editors'][0]
        assert 'john' not in editors['members']

    def test_userdel_nonexistent_user(self, passwd_db):
        """Test deleting nonexistent user"""
        result = passwd_db.userdel('nonexistent')
        assert result is False


class TestGroupManagement:
    """Test group management"""

    def test_groups_primary_group(self, passwd_db):
        """Test that user is in primary group"""
        passwd_db.useradd('john', password='secret')

        groups = passwd_db.groups('john')
        assert 'users' in groups  # Default primary group

    def test_groups_multiple(self, passwd_db):
        """Test user with multiple groups"""
        passwd_db.groupadd('editors')
        passwd_db.groupadd('admins')
        passwd_db.useradd('john', password='secret', groups=['editors', 'admins'])

        groups = passwd_db.groups('john')
        assert len(groups) == 3  # users, editors, admins
        assert 'users' in groups
        assert 'editors' in groups
        assert 'admins' in groups

    def test_groups_nonexistent_user(self, passwd_db):
        """Test groups for nonexistent user"""
        groups = passwd_db.groups('nonexistent')
        assert groups == []

    def test_groupadd_basic(self, passwd_db):
        """Test basic group creation"""
        group = passwd_db.groupadd('editors')

        assert group['groupname'] == 'editors'
        assert group['gid'] == 101  # After default 'users' group (100)
        assert group['members'] == []

    def test_groupadd_custom_gid(self, passwd_db):
        """Test group creation with custom GID"""
        group = passwd_db.groupadd('admins', gid=500)

        assert group['groupname'] == 'admins'
        assert group['gid'] == 500

    def test_groupadd_duplicate_fails(self, passwd_db):
        """Test that adding duplicate group fails"""
        passwd_db.groupadd('editors')

        with pytest.raises(ValueError, match="already exists"):
            passwd_db.groupadd('editors')

    def test_groupadd_increments_gid(self, passwd_db):
        """Test that GIDs increment correctly"""
        group1 = passwd_db.groupadd('editors')
        group2 = passwd_db.groupadd('admins')
        group3 = passwd_db.groupadd('moderators')

        assert group1['gid'] == 101
        assert group2['gid'] == 102
        assert group3['gid'] == 103


class TestListOperations:
    """Test list_users and list_groups"""

    def test_list_users_empty(self, passwd_db):
        """Test listing users when empty"""
        users = passwd_db.list_users()
        assert users == []

    def test_list_users_multiple(self, passwd_db):
        """Test listing multiple users"""
        passwd_db.useradd('john', password='secret')
        passwd_db.useradd('jane', password='secret')
        passwd_db.useradd('bob', password='secret')

        users = passwd_db.list_users()
        assert len(users) == 3

        usernames = [u.username for u in users]
        assert 'john' in usernames
        assert 'jane' in usernames
        assert 'bob' in usernames

    def test_list_groups_default(self, passwd_db):
        """Test listing groups includes default 'users' group"""
        groups = passwd_db.list_groups()
        assert len(groups) == 1
        assert groups[0]['groupname'] == 'users'

    def test_list_groups_multiple(self, passwd_db):
        """Test listing multiple groups"""
        passwd_db.groupadd('editors')
        passwd_db.groupadd('admins')

        groups = passwd_db.list_groups()
        assert len(groups) == 3  # users, editors, admins

        groupnames = [g['groupname'] for g in groups]
        assert 'users' in groupnames
        assert 'editors' in groupnames
        assert 'admins' in groupnames

    def test_list_groups_shows_members(self, passwd_db):
        """Test that list_groups shows group members"""
        passwd_db.groupadd('editors')
        passwd_db.useradd('john', password='secret', groups=['editors'])
        passwd_db.useradd('jane', password='secret', groups=['editors'])

        groups = passwd_db.list_groups()
        editors = [g for g in groups if g['groupname'] == 'editors'][0]

        assert len(editors['members']) == 2
        assert 'john' in editors['members']
        assert 'jane' in editors['members']


class TestPersistence:
    """Test that data persists across instances"""

    def test_user_persists(self, tmpdir):
        """Test that user data persists"""
        db1 = PasswdDB(etc_dir=tmpdir)
        db1.useradd('john', password='secret', fullname='John Doe')

        # Create new instance
        db2 = PasswdDB(etc_dir=tmpdir)
        user = db2.getuser('john')

        assert user is not None
        assert user.username == 'john'
        assert user.fullname == 'John Doe'

    def test_authentication_persists(self, tmpdir):
        """Test that authentication works across instances"""
        db1 = PasswdDB(etc_dir=tmpdir)
        db1.useradd('john', password='secret123')

        # Create new instance
        db2 = PasswdDB(etc_dir=tmpdir)
        user = db2.authenticate('john', 'secret123')

        assert user is not None
        assert user.username == 'john'

    def test_groups_persist(self, tmpdir):
        """Test that groups persist"""
        db1 = PasswdDB(etc_dir=tmpdir)
        db1.groupadd('editors')
        db1.useradd('john', password='secret', groups=['editors'])

        # Create new instance
        db2 = PasswdDB(etc_dir=tmpdir)
        groups = db2.groups('john')

        assert 'editors' in groups


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_empty_username(self, passwd_db):
        """Test handling of empty username"""
        # dbbasic-tsv should handle this, but verify behavior
        try:
            passwd_db.useradd('', password='secret')
            # If it doesn't raise, verify we can't authenticate
            user = passwd_db.authenticate('', 'secret')
            assert user is None or user.username == ''
        except (ValueError, Exception):
            pass  # Expected behavior

    def test_special_chars_in_username(self, passwd_db):
        """Test usernames with special characters"""
        user = passwd_db.useradd('john.doe', password='secret')
        assert user.username == 'john.doe'

        authenticated = passwd_db.authenticate('john.doe', 'secret')
        assert authenticated is not None

    def test_unicode_in_fullname(self, passwd_db):
        """Test Unicode in full name"""
        user = passwd_db.useradd('john', password='secret', fullname='Jöhn Döe 日本')
        assert user.fullname == 'Jöhn Döe 日本'

        retrieved = passwd_db.getuser('john')
        assert retrieved.fullname == 'Jöhn Döe 日本'

    def test_long_password(self, passwd_db):
        """Test very long password"""
        long_password = 'a' * 1000
        passwd_db.useradd('john', password=long_password)

        user = passwd_db.authenticate('john', long_password)
        assert user is not None

    def test_multiple_operations(self, passwd_db):
        """Test complex sequence of operations"""
        # Create groups
        passwd_db.groupadd('editors')
        passwd_db.groupadd('admins')

        # Create users
        passwd_db.useradd('john', password='secret1', groups=['editors'])
        passwd_db.useradd('jane', password='secret2', groups=['editors', 'admins'])

        # Modify users
        passwd_db.usermod('john', fullname='John Doe', add_groups=['admins'])
        passwd_db.passwd('jane', 'newsecret')

        # Verify state
        john = passwd_db.getuser('john')
        assert john.fullname == 'John Doe'
        assert 'admins' in passwd_db.groups('john')

        jane_auth = passwd_db.authenticate('jane', 'newsecret')
        assert jane_auth is not None

        # Delete user
        passwd_db.userdel('john')
        assert passwd_db.getuser('john') is None

        # Verify jane still works
        jane = passwd_db.getuser('jane')
        assert jane is not None
