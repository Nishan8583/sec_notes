# Testing

### Discover GraphQL endpoint
 - Graphql uses same endpoint for all actions.
 - Universal queries, send `query{__typename}` to any grapqhl endpoint, endpoints will respond with `{"data": {"__typename": "query"}}` somewhere in its response.
 - Common endpoints (maybe add v1,v2 ... to mix it up )
     - /graphql
     - /api
     - /api/graphql
     - /graphql/api
     -/graphql/graphql
 - GraphQL services will often respond to any non-GraphQL request with a `"query not present"` or similar error.
 - Usually they respond to `POST` if they don't, try different method with `x-www-form-urlencoded`.
 - If graphql powers the website, visit web UI, see HTTP history.
 - Burp scanner auto finds it and raises a issue, owasp zap too ?

### Exploiting unsanitized arguments
 - like IDOR
 - Example:
 - Request
```
#Example product query

    query {
        products {
            id
            name
            listed
        }
    }
```
 - Response
```
  #Example product response

    {
        "data": {
            "products": [
                {
                    "id": 1,
                    "name": "Product 1",
                    "listed": true
                },
                {
                    "id": 2,
                    "name": "Product 2",
                    "listed": true
                },
                {
                    "id": 4,
                    "name": "Product 4",
                    "listed": true
                }
            ]
        }
    }
```
 - See that ID is sequential  and id 3 is missing.
 - New Request
```
#Query to get missing product

    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
```
 - Check if we get response?

### Discovering schema information
 - Use introspection query. full query at https://portswigger.net/web-security/graphql.
 - inQL burp plugin.
 - Suggesstions ? https://github.com/nikitastupin/clairvoyance

### Bypassing GraphQL introspection defences
 - When developers disable introspection, they could use a regex to exclude the __schema keyword in queries. You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.
 - Alternate method?
```
 #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }
```

### LABS
##### Lab: Accessing private GraphQL posts
 - Looked at http history, sent data to inQL, Type the full URL in inQL scanner, I see
```
query {
	getBlogPost(id:1334) {
		date
		summary
		image
		author
		isPrivate
		title
		paragraphs
		id
		postPassword
	}
}
```
 -  `postPassword` is unique field, so turbo intruder with `postPassword` added to graphql fields, get the password.
