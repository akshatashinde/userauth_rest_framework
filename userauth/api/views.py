from django.db.models import Q
from django.contrib.auth import get_user_model

from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_205_RESET_CONTENT
from rest_framework.views import APIView
from django.utils.translation import gettext as _

from allauth.account import app_settings as allauth_settings
from django.contrib.auth import authenticate, login, logout
# from .models import User

from rest_framework.filters import (
        SearchFilter,
        OrderingFilter,
    )
from rest_framework.mixins import DestroyModelMixin, UpdateModelMixin
# from .models import TokenModel
# from .utils import jwt_encode

from rest_framework.generics import (
    CreateAPIView,
    DestroyAPIView,
    UpdateAPIView,
    ListAPIView,
    RetrieveAPIView,
    RetrieveUpdateAPIView,
    GenericAPIView,
    )

from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
    IsAdminUser,
    IsAuthenticatedOrReadOnly,

    )

from .serializers import ( 
    UserCreateSerializer,
    UserLoginSerializer,
    UserForgetPasswordSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    # LoginSerializer,
    )

User=get_user_model()

class PasswordChangeView(GenericAPIView):
    """
    Calls Django Auth SetPasswordForm save method.
    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    """

    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated,]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"success": _("New password has been saved.")})


class UserCreateAPIView(CreateAPIView):
    serializer_class = UserCreateSerializer
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    

class UserLoginAPIView(APIView):
    permission_classes = [AllowAny] 
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            new_data = serializer.data
            return Response(new_data, status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)     



class LogoutView(APIView):

    """
    Calls Django logout method and delete the Token object
    assigned to the current User object.
    Accepts/Returns nothing.
    """
    permission_classes = (AllowAny,)

    # def get(self, request, *args, **kwargs):
    #     try:
    #         if allauth_settings.LOGOUT_ON_GET:
    #             response = self.logout(request)
    #         else:
    #             response = self.http_method_not_allowed(request, *args, **kwargs)
    #     except Exception as exc:
    #         response = self.handle_exception(exc)

    #     return self.finalize_response(request, response, *args, **kwargs)

    # def post(self, request):
    #     return self.logout(request)

    # def logout(self, request):
    #     try:
    #         request.user.auth_token.delete()
    #     except (AttributeError, ObjectDoesNotExist):
    #         pass

    #     django_logout(request)

    #     return Response({"success": _("Successfully logged out.")},
    #                     status=status.HTTP_200_OK)
    def get(self, request):
        logout(request)
        return Response({"error": False, 'result': "logged out successfully"})

class PasswordResetView(GenericAPIView):

    """
    Calls Django Auth PasswordResetForm save method.
    Accepts the following POST parameters: email
    Returns the success/fail message.
    """

    serializer_class = PasswordResetSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        # Return the success message with OK HTTP status
        return Response(
            {"success": _("Password reset e-mail has been sent.")},
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(GenericAPIView):
    """
    Password reset e-mail link is confirmed, therefore this resets the user's password.
    Accepts the following POST parameters: new_password1, new_password2
    Accepts the following Django URL arguments: token, uid
    Returns the success/fail message.
    """

    serializer_class = PasswordResetConfirmSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"success": _("Password has been reset with the new password.")})

# class LoginView(GenericAPIView):

#     """
#     Check the credentials and return the REST Token
#     if the credentials are valid and authenticated.
#     Calls Django Auth login method to register User ID
#     in Django session framework
#     Accept the following POST parameters: username, password
#     Return the REST Framework Token Object's key.
#     """
#     permission_classes = (AllowAny,)
#     serializer_class = LoginSerializer
#     token_model = TokenModel

#     def process_login(self):
#         django_login(self.request, self.user)

#     def get_response_serializer(self):
#         if getattr(settings, 'REST_USE_JWT', False):
#             response_serializer = JWTSerializer
#         else:
#             response_serializer = TokenSerializer
#         return response_serializer

#     def login(self):
#         self.user = self.serializer.validated_data['user']

#         if getattr(settings, 'REST_USE_JWT', False):
#             self.token = jwt_encode(self.user)
#         else:
#             self.token = create_token(self.token_model, self.user, self.serializer)

#         if getattr(settings, 'REST_SESSION_LOGIN', True):
#             self.process_login()

#     def get_response(self):
#         serializer_class = self.get_response_serializer()

#         if getattr(settings, 'REST_USE_JWT', False):
#             data = {
#                 'user': self.user,
#                 'token': self.token
#             }
#             serializer = serializer_class(instance=data, context={'request': self.request})
#         else:
#             serializer = serializer_class(instance=self.token, context={'request': self.request})

#         return Response(serializer.data, status=status.HTTP_200_OK)

#     def post(self, request, *args, **kwargs):
#         self.request = request
#         self.serializer = self.get_serializer(data=self.request.data)
#         self.serializer.is_valid(raise_exception=True)

#         self.login()
#         return self.get_response()class LoginView(GenericAPIView):

#     """
#     Check the credentials and return the REST Token
#     if the credentials are valid and authenticated.
#     Calls Django Auth login method to register User ID
#     in Django session framework
#     Accept the following POST parameters: username, password
#     Return the REST Framework Token Object's key.
#     """
#     permission_classes = (AllowAny,)
#     serializer_class = LoginSerializer
#     token_model = TokenModel

#     def process_login(self):
#         django_login(self.request, self.user)

#     def get_response_serializer(self):
#         if getattr(settings, 'REST_USE_JWT', False):
#             response_serializer = JWTSerializer
#         else:
#             response_serializer = TokenSerializer
#         return response_serializer

#     def login(self):
#         self.user = self.serializer.validated_data['user']

#         if getattr(settings, 'REST_USE_JWT', False):
#             self.token = jwt_encode(self.user)
#         else:
#             self.token = create_token(self.token_model, self.user, self.serializer)

#         if getattr(settings, 'REST_SESSION_LOGIN', True):
#             self.process_login()

#     def get_response(self):
#         serializer_class = self.get_response_serializer()

#         if getattr(settings, 'REST_USE_JWT', False):
#             data = {
#                 'user': self.user,
#                 'token': self.token
#             }
#             serializer = serializer_class(instance=data, context={'request': self.request})
#         else:
#             serializer = serializer_class(instance=self.token, context={'request': self.request})

#         return Response(serializer.data, status=status.HTTP_200_OK)

#     def post(self, request, *args, **kwargs):
#         self.request = request
#         self.serializer = self.get_serializer(data=self.request.data)
#         self.serializer.is_valid(raise_exception=True)

#         self.login()
#         return self.get_response()