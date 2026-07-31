from django.urls import path

from . import views

app_name = 'lti_tool'

urlpatterns = [
    path('launch/', views.launch, name='launch'),
    path('chat/', views.chat, name='chat'),
    path('config.xml', views.config_xml, name='config_xml'),
    path('health/', views.health, name='health'),
]
