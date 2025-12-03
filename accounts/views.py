from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status

from .serializers import RegisterSerializer, UserSerializer


class RegisterView(APIView):
    def post(self, request: Request) -> Response:
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()

            user_json = UserSerializer(user).data

            return Response(user_json, status=status.HTTP_201_CREATED)
        
        return Response(status=status.HTTP_400_BAD_REQUEST)
