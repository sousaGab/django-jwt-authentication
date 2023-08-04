from django.shortcuts import render
from rest_framework import generics, response, status, views
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from django.urls import reverse
from django.conf import settings
from .utils import Util
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, ResetPasswordEmailSerializer, SetNewPasswordAPIViewSerializer
from .models import User
from .renderers import UserRenderer
import jwt
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util


class RegisterView(generics.GenericAPIView):
    
    serializer_class= RegisterSerializer
    renderer_classes = (UserRenderer,)
    
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        user_data = serializer.data
        
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        absurl = 'http://' + current_site + relative_link+'?token='+str(token)
        email_body = 'Hi '+ user.username + ' Use link below to verify your email \n' + absurl
        data = {'to_email': user.email,'email_body': email_body, 'email_subject': 'Verify your email'}
        Util.send_email(data)
        
        return response.Response(user_data,status= status.HTTP_201_CREATED)
        
        
class VerifyEmail(views.APIView):
    
    serializer_class = EmailVerificationSerializer

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "token", 
                OpenApiTypes.STR, 
                OpenApiParameter.QUERY, 
                description='Description',
            ),
        ],
    )
    
    def get(self, request):
        
        token = request.GET.get('token')
     
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            
            if not user.is_verified:
                user.is_verified = True
                user.save()
            
            return response.Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
            
        except jwt.ExpiredSignatureError as identifier:
            return response.Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
            
        except jwt.exceptions.DecodeError as identifier:
            return response.Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):
    
    serializer_class = LoginSerializer
    
    def post(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return response.Response(serializer.data, status=status.HTTP_200_OK)
    
class RequestPasswordResetEmail(generics.GenericAPIView):
    
    serializer_class = ResetPasswordEmailSerializer
    
    def post(self, request):
        
        serializer = self.serializer_class(data=request.data)
        
        email = request.data['email']
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(user.id)
            token = PasswordResetTokenGenerator().make_token(user)
            
            current_site = get_current_site(request=request).domain
            relative_link = reverse(
                'password-reset-confirm', 
                kwargs={'uidb64':uidb64, 'token':token})
            absurl = 'http://' + current_site + relative_link
            email_body = 'Hello, \n Use link below to reset your password \n' + absurl
            data = {'to_email': user.email,'email_body': email_body, 'email_subject': 'Reset your password'}
            Util.send_email(data)
    
        return response.Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        
        
class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                return response.Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            
            return response.Response({
                'success':True, 
                'message': 'Credentials Valid',
                'uidb64':uidb64, 
                'token':token},
                status=status.HTTP_200_OK)
            
        except DjangoUnicodeDecodeError as identifier:
            return response.Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
        
class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class= SetNewPasswordAPIViewSerializer

    def path(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return response.Response({'success':True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)