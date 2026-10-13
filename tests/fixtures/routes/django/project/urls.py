from django.urls import include, path

from billing import views as billing_views

urlpatterns = [
    path('shop/', include('shop.urls')),
    path('blog/', include('blog.urls')),
    path('invoices/<uuid:invoice_id>/', billing_views.invoice),
]
