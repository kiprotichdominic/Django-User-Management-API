from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(email, password, **extra_fields)


class CustomUser(AbstractUser, PermissionsMixin):
    SUBSCRIBER = 1
    CONTRIBUTOR = 2
    AUTHOR = 3
    EDITOR = 4
    ADMINISTRATOR = 5

    ROLE_CHOICES = (
        (SUBSCRIBER, 'Subscriber'),
        (CONTRIBUTOR, 'Contributor'),
        (AUTHOR, 'Author'),
        (EDITOR, 'Editor'),
        (ADMINISTRATOR, 'Administrator'),
    )

    username = models.CharField(max_length=150, unique=True)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default='subscriber')

    def __str__(self):
        return self.username
    objects = UserManager()

    class Meta:
        db_table = 'auth_user'

    @property
    def is_subscriber(self):
        return self.role == self.SUBSCRIBER

    @property
    def is_contributor(self):
        return self.role == self.CONTRIBUTOR

    @property
    def is_author(self):
        return self.role == self.AUTHOR

    @property
    def is_editor(self):
        return self.role == self.EDITOR

    @property
    def is_administrator(self):
        return self.role == self.ADMINISTRATOR

    def has_perm(self, perm, obj=None):
        if self.is_active and self.is_superuser:
            return True

        if self.is_active and self.is_staff:
            if perm in self.get_all_permissions():
                return True

        return False

    def has_module_perms(self, app_label):
        if self.is_active and self.is_superuser:
            return True

        if self.is_active and self.is_staff:
            if app_label in self.get_all_permissions():
                return True

        return False

    def get_role_permissions(self):
        if self.role == 'subscriber':
            return []
        elif self.role == 'contributor':
            return ['add_post', 'change_post']
        elif self.role == 'author':
            return ['add_post', 'change_post', 'delete_post', 'add_image']
        elif self.role == 'editor':
            return ['add_post', 'change_post', 'delete_post', 'add_image', 'add_category', 'change_category', 'delete_category', 'moderate_comments']
        elif self.role == 'administrator':
            return ['add_post', 'change_post', 'delete_post', 'add_image', 'add_category', 'change_category', 'delete_category', 'moderate_comments', 'add_user', 'change_user', 'delete_user']


# This code defines a custom user model in Django by
# subclassing AbstractUser and PermissionsMixin.
# The AbstractUser class provides the core implementation
# for a user model, and the PermissionsMixin class
# adds methods for handling permissions.
# The UserManager class is a custom manager
# for the User model, which provides two
# methods for creating users: create_user()
# and create_superuser(). The _create_user()
# method is a helper method that actually creates
# the user and saves it to the database.
# It takes an email and password as required arguments,
# and any additional fields as keyword arguments.
# The User model itself adds a role field, which is a
#  CharField with a choices attribute that defines the
# possible roles a user can have. The model also
# defines several properties that make it easy to
# check a user's role, such as is_subscriber, is_contributor, and so on.
# Finally, the model provides a method get_role_permissions()
# which returns a list of permissions that a user has based
# on their role. The permissions are defined as strings,
# such as add_post, change_post
