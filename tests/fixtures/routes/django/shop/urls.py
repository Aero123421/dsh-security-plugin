from django.urls import path, re_path

from . import views

urlpatterns = [
    path('', views.index),
    path('orders/<int:order_id>/', views.order_detail),
    path('account/', views.AccountView.as_view()),
    re_path(r'^archive/(?P<year>[0-9]{4})/$', views.archive),
]
