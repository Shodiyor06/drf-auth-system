from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Task
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        exclude = ['groups', 'user_permissions', 'is_staff', 'is_superuser', 'last_login']


class RegisterSerializer(serializers.ModelSerializer):
    confirm = serializers.CharField(max_length=128)

    class Meta:
        model = User
        fields = ['username', 'password', 'confirm', 'email', 'first_name', 'last_name']

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm']:
            raise serializers.ValidationError('password and confirm are nor the same value.')
        
        return super().validate(attrs)

    def create(self, validated_data):
        validated_data.pop('confirm')
        password = validated_data.pop('password')

        user = User(**validated_data)   
        user.set_password(password)
        user.save()

        return user
    

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128)


class ProfileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        exclude = ['password', 'role', 'groups', 'user_permissions', 'is_staff', 'is_superuser']
        extra_kwargs = {
            'username': {
                'required': False
            }
        }


class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)
    new_password = serializers.CharField(max_length=128)
    confirm = serializers.CharField(max_length=128)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm']:
            raise serializers.ValidationError('password and confirm are nor the same value.')
        
        return super().validate(attrs)


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'
        read_only_fields = ('user',)
