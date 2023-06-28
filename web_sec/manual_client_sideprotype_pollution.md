# Client Side
In your browser, try polluting Object.prototype by injecting an arbitrary property via the query string:

/?__proto__[foo]=bar
Open the browser DevTools panel and go to the Console tab.

Enter Object.prototype.

Study the properties of the returned object and observe that your injected foo property has not been added.

Back in the query string, try using an alternative prototype pollution vector:

/?__proto__.foo=bar
In the console, enter Object.prototype again. Notice that it now has its own foo property with the value bar. You've successfully found a prototype pollution source.

Identify a gadget

In the browser DevTools panel, go to the Sources tab.

Study the JavaScript files that are loaded by the target site and look for any DOM XSS sinks.

Notice that there is an eval() sink in searchLoggerAlternative.js.

Notice that the manager.sequence property is passed to eval(), but this isn't defined by default.
