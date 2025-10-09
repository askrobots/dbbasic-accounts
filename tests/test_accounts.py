"""
Tests for dbbasic_accounts.Accounts (web-friendly API)
"""

import pytest
import tempfile
import shutil
from pathlib import Path

from dbbasic_accounts import Accounts, User


class TestAccounts:
    """Test Accounts class (web-friendly API)"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        tmpdir = tempfile.mkdtemp()
        yield tmpdir
        shutil.rmtree(tmpdir)

    @pytest.fixture
    def accounts(self, temp_dir):
        """Create Accounts instance"""
        return Accounts(temp_dir, domain='example.com')

    def test_init_creates_directories(self, temp_dir):
        """Test that init creates required directories"""
        accounts = Accounts(temp_dir, domain='test.com')

        assert (Path(temp_dir) / 'etc').exists()
        assert (Path(temp_dir) / 'home').exists()
        assert (Path(temp_dir) / 'var').exists()
        assert (Path(temp_dir) / 'var' / 'mail').exists()

    def test_init_creates_tsv_files(self, temp_dir):
        """Test that init creates TSV files"""
        accounts = Accounts(temp_dir, domain='test.com')

        assert (Path(temp_dir) / 'etc' / 'passwd.tsv').exists()
        assert (Path(temp_dir) / 'etc' / 'shadow.tsv').exists()
        assert (Path(temp_dir) / 'etc' / 'group.tsv').exists()

    def test_register_creates_user(self, accounts):
        """Test registering a new user"""
        user = accounts.register('john@example.com', 'secret123', name='John Doe')

        assert isinstance(user, User)
        assert user.username == 'john'
        assert user.fullname == 'John Doe <john@example.com>'
        assert user.uid == 1000

    def test_register_creates_home_directory(self, accounts, temp_dir):
        """Test that register creates home directory"""
        accounts.register('john@example.com', 'secret123')

        home_dir = Path(temp_dir) / 'home' / 'john'
        assert home_dir.exists()
        assert (home_dir / 'uploads').exists()

    def test_register_creates_mailbox(self, accounts, temp_dir):
        """Test that register creates mailbox"""
        accounts.register('john@example.com', 'secret123')

        mailbox = Path(temp_dir) / 'var' / 'mail' / 'john'
        assert mailbox.exists()

    def test_register_duplicate_fails(self, accounts):
        """Test that registering duplicate user fails"""
        accounts.register('john@example.com', 'secret123')

        with pytest.raises(ValueError, match="already exists"):
            accounts.register('john@example.com', 'secret456')

    def test_login_valid_credentials(self, accounts):
        """Test login with valid credentials"""
        accounts.register('john@example.com', 'secret123', name='John Doe')

        user = accounts.login('john@example.com', 'secret123')

        assert user is not None
        assert user.username == 'john'

    def test_login_invalid_password(self, accounts):
        """Test login with invalid password"""
        accounts.register('john@example.com', 'secret123')

        user = accounts.login('john@example.com', 'wrongpassword')

        assert user is None

    def test_login_nonexistent_user(self, accounts):
        """Test login with nonexistent user"""
        user = accounts.login('nobody@example.com', 'password')

        assert user is None

    def test_get_user_by_email(self, accounts):
        """Test getting user by email"""
        accounts.register('john@example.com', 'secret123', name='John Doe')

        user = accounts.get_user(email='john@example.com')

        assert user is not None
        assert user.username == 'john'

    def test_get_user_by_username(self, accounts):
        """Test getting user by username"""
        accounts.register('john@example.com', 'secret123', name='John Doe')

        user = accounts.get_user(username='john')

        assert user is not None
        assert user.username == 'john'

    def test_get_user_by_id(self, accounts):
        """Test getting user by ID"""
        registered = accounts.register('john@example.com', 'secret123')

        user = accounts.get_user(user_id=registered.uid)

        assert user is not None
        assert user.username == 'john'
        assert user.uid == registered.uid

    def test_get_user_not_found(self, accounts):
        """Test getting nonexistent user"""
        user = accounts.get_user(email='nobody@example.com')

        assert user is None

    def test_add_role(self, accounts):
        """Test adding role to user"""
        accounts.register('john@example.com', 'secret123')

        result = accounts.add_role('john@example.com', 'editor')

        assert result is True
        roles = accounts.get_roles('john@example.com')
        assert 'editor' in roles

    def test_remove_role(self, accounts):
        """Test removing role from user"""
        accounts.register('john@example.com', 'secret123')
        accounts.add_role('john@example.com', 'editor')

        result = accounts.remove_role('john@example.com', 'editor')

        assert result is True
        roles = accounts.get_roles('john@example.com')
        assert 'editor' not in roles

    def test_get_roles(self, accounts):
        """Test getting user roles"""
        accounts.register('john@example.com', 'secret123')
        accounts.add_role('john@example.com', 'editor')
        accounts.add_role('john@example.com', 'admin')

        roles = accounts.get_roles('john@example.com')

        assert 'users' in roles  # default group
        assert 'editor' in roles
        assert 'admin' in roles

    def test_change_password(self, accounts):
        """Test changing password"""
        accounts.register('john@example.com', 'secret123')

        result = accounts.change_password('john@example.com', 'newsecret456')

        assert result is True

        # Old password should not work
        user = accounts.login('john@example.com', 'secret123')
        assert user is None

        # New password should work
        user = accounts.login('john@example.com', 'newsecret456')
        assert user is not None

    def test_delete_user(self, accounts):
        """Test deleting user"""
        accounts.register('john@example.com', 'secret123')

        result = accounts.delete_user('john@example.com')

        assert result is True

        # User should not exist anymore
        user = accounts.get_user(email='john@example.com')
        assert user is None

    def test_delete_nonexistent_user(self, accounts):
        """Test deleting nonexistent user"""
        result = accounts.delete_user('nobody@example.com')

        assert result is False

    def test_list_users(self, accounts):
        """Test listing all users"""
        accounts.register('john@example.com', 'secret123', name='John Doe')
        accounts.register('jane@example.com', 'pass456', name='Jane Smith')

        users = accounts.list_users()

        assert len(users) == 2
        usernames = [u.username for u in users]
        assert 'john' in usernames
        assert 'jane' in usernames

    def test_get_home_directory(self, accounts, temp_dir):
        """Test getting home directory path"""
        accounts.register('john@example.com', 'secret123')

        home = accounts.get_home_directory('john@example.com')

        assert home is not None
        assert home == Path(temp_dir) / 'home' / 'john'
        assert home.exists()

    def test_get_home_directory_nonexistent_user(self, accounts):
        """Test getting home directory for nonexistent user"""
        home = accounts.get_home_directory('nobody@example.com')

        assert home is None

    def test_get_mailbox(self, accounts, temp_dir):
        """Test getting mailbox path"""
        accounts.register('john@example.com', 'secret123')

        mailbox = accounts.get_mailbox('john@example.com')

        assert mailbox is not None
        assert mailbox == Path(temp_dir) / 'var' / 'mail' / 'john'
        assert mailbox.exists()

    def test_get_mailbox_nonexistent_user(self, accounts):
        """Test getting mailbox for nonexistent user"""
        mailbox = accounts.get_mailbox('nobody@example.com')

        assert mailbox is None

    def test_email_to_username_extraction(self, accounts):
        """Test username extraction from email"""
        user = accounts.register('john.doe@example.com', 'secret123')

        assert user.username == 'john.doe'

    def test_multiple_users_different_uids(self, accounts):
        """Test that multiple users get different UIDs"""
        user1 = accounts.register('john@example.com', 'secret123')
        user2 = accounts.register('jane@example.com', 'pass456')

        assert user1.uid != user2.uid
        assert user1.uid == 1000
        assert user2.uid == 1001

    def test_unix_layer_accessible(self, accounts):
        """Test that underlying PasswdDB layer is accessible"""
        accounts.register('john@example.com', 'secret123')

        # Access Unix layer directly
        user = accounts.passwd.getuser('john')

        assert user is not None
        assert user.username == 'john'
