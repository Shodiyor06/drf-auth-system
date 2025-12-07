from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    message = 'siz amdin emassiz'

    def has_permission(self, request, view):
        return request.user and request.user.is_admin
    
class IsManager(BasePermission):
    message = 'siz manager emassiz'

    def has_permission(self, request, view):
        return request.user and request.user.is_manager
    
class IsUser(BasePermission):
    message = 'siz user emassiz'

    def has_permission(self, request, view):
        return request.user and request.user.is_user

class IsStaff(BasePermission):
    message = 'siz staff emassiz'

    def has_permission(self, request, view):
        return request.user and not (request.user.is_amdin or request.user.is_manager)
