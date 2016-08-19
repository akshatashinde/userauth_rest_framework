from django.db.models import Q
from django.contrib.auth import get_user_model

from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_205_RESET_CONTENT
from rest_framework.views import APIView
from django.utils.translation import gettext as _

from allauth.account import app_settings as allauth_settings
from django.contrib.auth import authenticate, login, logout

from rest_framework.filters import (
        SearchFilter,
        OrderingFilter,
    )
from rest_framework.mixins import DestroyModelMixin, UpdateModelMixin

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
    ResetSerializer,
    UserForgetPasswordSerializer,
    UserSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
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



class UserChangePassword(APIView):
        serializer_class = UserSerializer()
        def patch(self, request):
            user = self.request.user
            serialized = UserSerializer()
            if serialized.is_valid():
                user.set_password(serialized.data['password'])
                user.save()
                return Response()
            else:
                return Response(serialized.errors, status=status.HTTP_400_BAD_REQUEST)

class UserResetAPIView(CreateAPIView):
    serializer_class = ResetSerializer
    queryset = User.objects.all()
    permission_classes = [AllowAny]

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

class UserForgetPasswordAPIView(CreateAPIView):
    serializer_class = UserForgetPasswordSerializer
    queryset = User.objects.all()
    permission_classes = [AllowAny]

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

