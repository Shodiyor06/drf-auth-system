from django.db import models
from django.contrib.auth.models import AbstractUser


class CustomUser(models.Model):
    ROLES = [
        ['ADMIN', 'Admin'],
        ['USER', 'User'],
        ['MANAGER', 'Manager'],
    ]

    role = models.CharField(
        choices=ROLES,
        default='USER'
    )

    @property
    def is_admin(self):
        return self.role == 'ADMIN'

    @property
    def is_user(self):
        return self.role == 'USER'

    @property
    def is_manager(self):
        return self.role == 'MANAGER'
    


class Task(models.Model):
    STATUS = (
        ('done', 'Done'),
        ('pending', 'Pending'),
    )

    title = models.CharField(max_length=255)
    user = models.ForeignKey(AbstractUser, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

