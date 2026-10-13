from django.contrib.auth.decorators import permission_required


@permission_required('billing.view_invoice')
def invoice(request, invoice_id):
    return HttpResponse(str(invoice_id))
