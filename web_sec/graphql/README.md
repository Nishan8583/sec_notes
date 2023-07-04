# Primer
 - Source: https://portswigger.net/web-security/graphql/what-is-graphql
 - GraphQL is an API query language that is designed to facilitate efficient communication between clients and servers. It enables the user to specify exactly what data they want in the response, helping to avoid the large response objects and multiple calls that can sometimes be seen with REST APIs.
 - All GraphQL operations use the same endpoint, and are generally sent as a POST request. This is significantly different to REST APIs, which use operation-specific endpoints across a range of HTTP methods. With GraphQL, the type and name of the operation define how the query is handled, rather than the endpoint it is sent to or the HTTP method used.
 - GraphQL services generally respond to operations with a JSON object in the structure requested.
 - In GraphQL, the schema represents a contract between the frontend and backend of the service. It defines the data available as a series of types, using a human-readable schema definition language.
```
 #Example schema definition

    type Product {
        id: ID!
        name: String!
        description: String!
        price: Int
    }
```
 - The example below shows a getEmployee request that takes an employee ID as an argument. In this case, the server responds with only the details of the employee who matches that ID.
```
 #Example query with arguments

    query myGetEmployeeQuery {
        getEmployees(id:1) {
            name {
                firstname
                lastname
            }
        }
    }
```
