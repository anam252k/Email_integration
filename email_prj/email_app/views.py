from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from email_app.renderers import UserRenderer
from email_app.serializers import UserRegisterationSerializer,UserLoginSerializers,UserProfileSerializer,UserChangePasswordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

from django.core.mail import send_mail
from django.conf import settings

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegisterationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
        serializer = UserRegisterationSerializer(data=request.data)
        if serializer.is_valid():
            user=serializer.save()
            token = get_tokens_for_user(user)

            # Send a welcome email
            subject = 'Welcome to Your Website'
            message = 'Thank you for registering on Your Website. We hope you enjoy our services.'
            from_email = settings.EMAIL_HOST_USER  # Use your SMTP email address
            recipient_list = [user.email]  # Replace with the user's email address

            try:
                send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            except Exception as e:
                return Response({'error': 'Failed to send welcome email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'token':token,'msg':'registeration successfull'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializers(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token,'msg':'Login Successful'},status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non-field_errors':['Email or Password is not valid']}},status=status.HTTP_404_NOT_FOUND)
        return Response({'msg':'Login Successful'},status=status.HTTP_200_OK)
    
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes=[IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK) 
    
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes=[IsAuthenticated]
    def post(self,request):
        serializer= UserChangePasswordSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid():
            return Response({'msg':'password change successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)