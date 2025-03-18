from rest_framework_api.views import StandardAPIView
from rest_framework import permissions
from django.contrib.auth import get_user_model
import pyotp
from io import BytesIO
from django.contrib.auth.hashers import make_password
import qrcode
from django.core.files.base import ContentFile
from django.utils.crypto import get_random_string
User=get_user_model()
from utils.client_ip import get_client_ip
from django.utils import timezone




class GenerateQRCodeView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        email=user.email
        
        otp_base32=pyotp.random_base32()
        
        ot_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
            name= email.lower(),
            issuer_name="zenith",
        )
        
        stream= BytesIO()
        image = qrcode.make(f"{ot_auth_url}")
        image.save(stream)
        
        user.otp_base32= otp_base32
        user.qr_code=ContentFile(
            stream.getvalue(),
            name=f"{get_random_string(10)}.png",
            )
        
        user.save()
        qr_code = user.qr_code
        return self.response(qr_code.url)
    
class OTPLoginResetView(StandardAPIView):
    permissions_classes = [permissions.IsAuthenticated]
    
    def post (self,request):
        user = request.user
        
        new_ip=get_client_ip
        
        if user.login_ip and user.login_ip != new_ip:
            print(f"New Login IP user{user.email}")
            
        user.login_ip=new_ip
        
        if user.qrcode is None or user.otp_base32 is None:
            return self.response("QR Code or OTP Base32 not found for user")
        
        try: 
            totp=pyotp.TOTP(user.otp_base32).now()
        except Exception as e:
            return self.error(f"error generate TOPT {str(e)}")
        
        user.login_otp=make_password(totp)
        user.otp_created_at=timezone.now()
        user.login_otp_used=False
        user.save() 
        return self.response("OTP Reset Successfully")


class VerifyOTPView(StandardAPIView):
    permissions_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        
        
        if user.qrcode is None or user.otp_base32 is None:
            return self.response("QR Code or OTP Base32 not found for user")
        
        totp=pyotp.TOTP(user.otp_base32)
        otp=request.data.get("otp")
        verified=totp.verify(otp)
        
        if  verified:
            user.login_otp_used=True
            user.save()
            return self.response("OTP Verified")
        else:
            return self.error("Error Verifiying one time Password")
        
class DisableOTPView(StandardAPIView):
    permissions_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        
        if user.qrcode is None or user.otp_base32 is None:
            return self.response("QR Code or OTP Base32 not found for user")
        
        totp=pyotp.TOTP(user.otp_base32)
        otp=request.data.get("otp")
        verified=totp.verify(otp)
        
        if  verified:
            user.two_factor_auth_enabled=False
            user.otpauth_url=None
            user.otp_base32=None
            user.qr_code=None
            user.login_otp=None
            user.login_otp_used=None
            user.otp_created_at=None
            user.save()
            return self.response("Two Factor Authentication Disabled")
        else:
            return self.error("Error Verifiying one time Password")


class Set2FAView(StandardAPIView):  # Define una vista llamada Set2FAView, heredando de StandardAPIView
    permissions_classes = [permissions.IsAuthenticated]  # Configura los permisos: solo usuarios autenticados pueden acceder

    def post(self, request, *args, **kwargs):  # Define el método POST para manejar las solicitudes POST
        user = request.user  # Obtiene el usuario autenticado de la solicitud

        if user.qrcode is None:  # Verifica si el usuario tiene un código QR configurado
            return self.error("QR Code not found for user")  # Si no, devuelve un error (asumiendo self.error existe)

        boolean = bool(request.data.get("bool"))  # Obtiene el valor 'bool' del cuerpo de la solicitud y lo convierte a booleano

        if boolean:  # Si el booleano es True
            user.two_factor_auth_enabled = True  # Habilita la autenticación de dos factores para el usuario
            user.save()  # Guarda los cambios en el usuario
            return self.response("2FA aCTIVATED")  # Devuelve una respuesta de éxito (asumiendo self.response existe)
        else:  # Si el booleano es False
            user.two_factor_auth_enabled = False  # Deshabilita la autenticación de dos factores para el usuario
            user.save()  # Guarda los cambios en el usuario
            return self.response("2FA DEACTIVATED")  # Devuelve una respuesta de éxito (asumiendo self.response existe)
    