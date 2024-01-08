# NoSQL Injection
- NoSQL injection is a vulnerability where an attacker is able to interfere with the queries that an application makes to a NoSQL database.
- Two types:
    -  Syntax injection - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. The methodology is similar to that used in SQL injection. However the nature of the attack varies significantly, as NoSQL databases use a range of query languages, types of query syntax, and different data structures.
    - Operator injection - This occurs when you can use NoSQL query operators to manipulate queries.

## NoSQL syntax injection
### Detecting syntax injection in MongoDB

- original request`https://insecure-website.com/product/lookup?category=fizzy`
- in backend`this.category == 'fizzy'`
- Test with payload``'"`{ ;$Foo} $Foo \xYZ``

#### Determining which characters are processed
- Send single character <!--StartFragment-->

this.category == '' ' 	'

<!--EndFragment-->

#### Confirming conditional behavior
- <!--StartFragment-->

`' && 0 && 'x` and `' && 1 && 'x`

<!--EndFragment-->
- Override with <!--StartFragment-->

'||1||'

<!--EndFragment-->

### Errors to lookout for
<!--StartFragment-->

Command failed with error 139 (JSInterpreterFailure): 'SyntaxError: unterminated string literal : functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25 ' on server 127.0.0.1:27017. The full response is {"ok": 0.0, "errmsg": "SyntaxError: unterminated string literal :\nfunctionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25\n", "code": 139, "codeName": "JSInterpreterFailure"}

<!--EndFragment-->

# Interesting lab
- In many NoSQL databases, some query operators or functions can run limited JavaScript code, such as MongoDB's `$where` operator and `mapReduce()` function.
- Look at the solution here https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data .
