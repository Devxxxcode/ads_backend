from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserAuthViewSet, InvitationCodeViewSet, AdminAuthViewSet

# Create a router and register the ViewSets
router = DefaultRouter()
router.register(r'', UserAuthViewSet, basename='auth')
router.register(r'invitation-codes', InvitationCodeViewSet, basename='auth')
router.register(r'admin', AdminAuthViewSet, basename='admin')

urlpatterns = [
    path('', include(router.urls)), 
]
