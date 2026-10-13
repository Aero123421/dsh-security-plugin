from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View


def index(request):
    return HttpResponse('shop')


@login_required
def order_detail(request, order_id):
    return HttpResponse(str(order_id))


class AccountView(LoginRequiredMixin, View):
    def get(self, request):
        return HttpResponse('account')


def archive(request, year):
    return HttpResponse(year)
