from django.contrib.auth import get_user_model, login, logout
from django.http import JsonResponse
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import ChangePasswordSerializer, UserRegisterSerializer, UserLoginSerializer, UserSerializer
from rest_framework import permissions, status
from .validations import custom_validation, validate_email, validate_password
from django.views.decorators.csrf import csrf_exempt

UserModel = get_user_model()
@csrf_exempt
def getcsrftoken(request):
    return JsonResponse({'csrfToken': request.META.get('CSRF_TOKEN')})

class UserRegister(APIView):
	permission_classes = (permissions.AllowAny,)
	def post(self, request):
		clean_data = custom_validation(request.data)
		# clean_data = request.data
		serializer = UserRegisterSerializer(data=clean_data)
		if serializer.is_valid(raise_exception=True):
			user = serializer.create(clean_data)
			if user:
				return Response(serializer.data, status=status.HTTP_200_OK)
		return Response(status=status.HTTP_400_BAD_REQUEST)

class UserLogin(APIView):
	permission_classes = (permissions.AllowAny,)
	authentication_classes = (SessionAuthentication,)
	##
	def post(self, request):
		data = request.data
		assert validate_email(data)
		assert validate_password(data)
		serializer = UserLoginSerializer(data=data)
		if serializer.is_valid(raise_exception=True):
			user = serializer.check_user(data)
			login(request, user)
			response = {
				"user" : serializer.data,
				"message": "Login Successful",
				"session_id": request.session.session_key  # Include the session_id in the response
			}
			return Response(data=response, status=status.HTTP_200_OK)



class UserLogout(APIView):
	permission_classes = (permissions.AllowAny,)
	authentication_classes = ()
	def post(self, request):
		logout(request)
		return Response(status=status.HTTP_200_OK)

# class UserLogout(APIView):
# 	permission_classes = (permissions.AllowAny,)
# 	serializer_class = LogoutSerializer
# 	authentication_classes = (SessionAuthentication,)
# 	def post(self, request, *args, **kwargs):
# 		request.auth.delete()
# 		return Response({"message": "User logged out successfully"}, status=status.HTTP_200_OK)


class UserView(APIView):
	permission_classes = (permissions.IsAuthenticated,)
	authentication_classes = (SessionAuthentication,)
	##
	def get(self, request):
		serializer = UserSerializer(request.user)
		return Response({'user': serializer.data}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
	# permission_classes = (permissions.IsAuthenticated,)
	# authentication_classes = (SessionAuthentication,)
	def post(self, request, *args, **kwargs):
		print("dddddddddddd")
		serializer = ChangePasswordSerializer(data=request.data)
		print(request.user)
		serializer.is_valid(raise_exception=True)
		user = request.user
		user.set_password(serializer.data.get("new_password"))
		print("hiiiiiiiiiiiiiiiiiiii")
		user.save()
		return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
