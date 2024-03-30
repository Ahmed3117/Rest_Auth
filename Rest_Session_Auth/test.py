import http.client

conn = http.client.HTTPConnection("127.0.0.1:8000")

payload = "{\n    \"password\": \"ahmedissa5\",\n\t  \"username\": \"ahmedissa5\",\n    \"email\": \"ahmedissa5@gmail.com\"\n}"

headers = {
    'cookie': "csrftoken=UeMOr9klGqImD1HSXuGUc8RCGWMxRBbw; sessionid=o5lcl7oi2giownccil99ew1w10t2wph7",
    'Content-Type': "application/json",
    'User-Agent': "insomnia/8.6.1"
    }

conn.request("POST", "/accounts/register", payload, headers)

res = conn.getresponse()
data = res.read()

print(data.decode("utf-8"))