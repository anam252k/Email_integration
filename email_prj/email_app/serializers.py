from django.conf import settings
from rest_framework import serializers
from email_app.models import User
from xml.dom import ValidationErr
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail


class UserRegisterationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }

    #validdating password and confirm password while registration
    def validate(self,attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and confirm Password doesn't match")
        return attrs
    
    def create(self,validate_data):
        return User.objects.create_user(**validate_data)
    

class UserLoginSerializers(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email','password']

class UserProfileSerializer(serializers.ModelSerializer):
     class Meta:
        model = User
        fields = ['id','email','name']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)

    class Meta:
        model = User
        fields = ['password','password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        # model = User
        fields = ['email']

    def validate(self,attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID',uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token',token)
            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            print('Password Reset link',link)

            if user:
                subject = 'Reset Your Password'
                message = f'Click the following link to reset your password: {link}'
                from_email = settings.EMAIL_HOST_USER  # Use your SMTP email address
                recipient_list = [user.email]  # Replace with the user's email address

                try:
                    send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                    return attrs
                except Exception as e:
                    raise ValidationErr('Failed to send password reset email.')

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password =attrs.get('password')
            password2 =attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError("Password and confirm Password doesn't match")
            id= smart_str(urlsafe_base64_decode(uid))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationErr('Token is not valid or Expired')
            user.set_password(password)
            user.save()
            return attrs

        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationErr('Token is not valid or Expired')