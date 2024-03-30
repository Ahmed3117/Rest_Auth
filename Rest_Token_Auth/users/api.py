# views functions that i created in model
from rest_framework import status
from rest_framework.response import Response

from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import CreateAPIView, UpdateAPIView
from django.contrib.auth import get_user_model
from rest_framework.authentication import TokenAuthentication
from .serializers import RegisterSerializer, LoginSerializer, LogoutSerializer, ChangePasswordSerializer
from django.contrib.auth import authenticate
from rest_framework.views import APIView
# from .tokens import create_jwt_pair_for_user
User = get_user_model()
from rest_framework import permissions
class RegisterView(CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = []

    def post(self, request):
        data = request.data

        serializer = self.serializer_class(data=data)

        if serializer.is_valid():
            serializer.save()

            response = {"message": "User Created Successfully", "data": serializer.data}

            return Response(data=response, status=status.HTTP_201_CREATED)

        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(email=email, password=password)

        if user is not None:
            token, _ = Token.objects.get_or_create(user=user)
            response = {"message": "Login Successful", "token": token.key}
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            return Response(data={"message": "Invalid email or password"})

    def get(self, request):
        content = {"user": str(request.user), "auth": str(request.auth)}

        return Response(data=content, status=status.HTTP_200_OK)

# class LoginView(APIView):
#     def post(self, request):
#         user = authenticate(username=request.data['username'], password=request.data['password'])
#         if user:
#             token, created = Token.objects.get_or_create(user=user)
#             return Response({'token': created,'token': token})
#         else:
#             return Response({'error': 'Invalid credentials'}, status=401)

class LogoutView(UpdateAPIView):
    serializer_class = LogoutSerializer

    def post(self, request, *args, **kwargs):
        request.auth.delete()
        return Response({"message": "User logged out successfully"}, status=status.HTTP_200_OK)

class ChangePasswordView(UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ChangePasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        user.set_password(serializer.data.get("new_password"))
        user.save()
        return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)












