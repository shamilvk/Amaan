from django.shortcuts import render, redirect
from django.http import HttpResponse
from carts.models import CartItem
from .forms import OrderForm
import datetime
from .models import Order, Payment
import json


def payments(request):
    body = json.loads(request.body)
    order = Order.objects.get(user=request.user, is_ordered=False, order_number=body['orderID'])
    print(body)
    #Store transaction details inside payment model
    # payment = Payment(
    #     user = request.user,
    #     payment_id  = body['transID'],
    #     payment_method = body['payment_method'],
    #     amount_paid = order.order_total,
    #     status = body['status'],
    # )
    # payment.save()
    # order.payment = payment
    # order.is_ordered = True
    # order.save()
    return redirect('home')



def place_order(request, total=0, quantity=0,):
    current_user = request.user
    
    #If the cart count is less thon or equal to 0, then redireact back to shop
    cart_items = CartItem.objects.filter(user=current_user)
    cart_count = cart_items.count()
    if cart_count <=0:
        return redirect('store')
    
    grand_total = 0
    tax = 0
    for cart_item in cart_items:
        total += (cart_item.product.price * cart_item.quantity)
        quantity += cart_item.quantity
    tax = (3 * total)/100
    grand_total = total + tax
    
    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            #Store all the billing information inside Order table
            date = Order()
            date.user = current_user
            date.first_name = form.cleaned_data['first_name']
            date.last_name = form.cleaned_data['last_name']
            date.phone = form.cleaned_data['phone']
            date.email = form.cleaned_data['email']
            date.address_line_1 = form.cleaned_data['address_line_1']
            date.address_line_2 = form.cleaned_data['address_line_2']
            date.country = form.cleaned_data['country']
            date.state = form.cleaned_data['state']
            date.city = form.cleaned_data['city']
            date.order_note = form.cleaned_data['order_note']
            date.order_total = grand_total
            date.tax = tax
            date.ip = request.META.get('REMOTE_ADDR')
            date.save()
            # Generate order number
            
            yr = int(datetime.date.today().strftime('%Y'))
            dt = int(datetime.date.today().strftime('%d'))
            mt = int(datetime.date.today().strftime('%m'))
            d = datetime.date(yr, mt, dt)
            current_date = d.strftime("%Y%m%d") 
            order_number = current_date + str(date.id)
            date.order_number = order_number
            date.save()
            
            order = Order.objects.get(user=current_user, is_ordered=False, order_number=order_number)
            context = {
                'order':order,
                'cart_items':cart_items,
                'total' : total,
                'tax' : tax,
                'grand_total' : grand_total,
                
            }
            return render(request, 'orders/payments.html', context)
        
    else:
        return redirect('checkout')
        