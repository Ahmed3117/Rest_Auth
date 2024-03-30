from django.shortcuts import render

# Create your views here.

def testpage(request):
    return render(request, 'testapp/test.html')