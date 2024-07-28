A Unix socket (or Unix domain socket) is a mechanism in Unix-like operating systems for inter-process communication (IPC). It allows data exchange between processes running on the same machine, using the file system as a communication medium rather than network interfaces. Here's an overview of Unix sockets:
Key Points

    Purpose:
        Facilitate communication between processes on the same host.
        Used for high-performance and efficient data transfer between local applications.

    Types:
        Stream Sockets (SOCK_STREAM): Provide a reliable, connection-oriented byte stream. Similar to TCP sockets.
        Datagram Sockets (SOCK_DGRAM): Provide connectionless, unreliable message-passing. Similar to UDP sockets.
        Sequenced Packet Sockets (SOCK_SEQPACKET): Provide a connection-oriented, sequenced, reliable message-passing service.

    Advantages:
        Performance: Faster than network sockets (e.g., TCP/IP) because they avoid network stack overhead.
        Security: Utilize file system permissions, providing finer control over access compared to network sockets.

    Usage:
        Commonly used by applications that require fast communication, such as databases (e.g., MySQL, Redis) and services within the same host.
        Applications open a Unix socket file (typically found in /tmp or /var/run) and use it to send and receive data.

    File System Integration:
        Unix sockets appear as special files in the file system.
        The socket file path (e.g., /var/run/docker.sock) is used by applications to connect to the socket.


Communication Breakdown

    Server Sends Data to Client:
        Server: conn.Write([]byte("Hello from server!"))
        Client: conn.Read(buf) → Receives "Hello from server!"

    Client Sends Data to Server:
        Client: conn.Write([]byte("Hello from client!"))
        Server: conn.Read(buf) → Receives "Hello from client!"

Explanation of Data Handling

    Socket File: The socket file at /tmp/unix_socket_example is a special file that facilitates the connection. It doesn’t store the data itself; it merely acts as a reference point for the communication channel.
    Connection Objects: The net.Conn objects handle the actual data transmission. Data written to these objects is transmitted over the Unix domain socket to the corresponding endpoint.

The server and client use these connection objects to read and write data. The operating system ensures that data written by one endpoint is correctly transmitted and made available to the other endpoint, preventing any mix-up where the server would read its own data or the client would read its own data.

GO Server code 
```go
package main

import (
    "fmt"
    "log"
    "net"
    "os"
)

func main() {
    socketPath := "/tmp/unix_socket_example"

    // Remove the socket file if it already exists
    if err := os.RemoveAll(socketPath); err != nil {
        log.Fatal(err)
    }

    // Create a Unix socket listener
    listener, err := net.Listen("unix", socketPath)
    if err != nil {
        log.Fatal("Listen error:", err)
    }
    defer listener.Close()

    fmt.Println("Server is listening on", socketPath)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Fatal("Accept error:", err)
        }

        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    buf := make([]byte, 1024)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            log.Println("Read error:", err)
            return
        }

        log.Printf("Received: %s", string(buf[:n]))

        // Echo the message back to the client
        _, err = conn.Write(buf[:n])
        if err != nil {
            log.Println("Write error:", err)
            return
        }
    }
}
```
Go client code
```go
package main

import (
    "fmt"
    "log"
    "net"
    "os"
)

func main() {
    socketPath := "/tmp/unix_socket_example"

    // Remove the socket file if it already exists
    if err := os.RemoveAll(socketPath); err != nil {
        log.Fatal(err)
    }

    // Create a Unix socket listener
    listener, err := net.Listen("unix", socketPath)
    if err != nil {
        log.Fatal("Listen error:", err)
    }
    defer listener.Close()

    fmt.Println("Server is listening on", socketPath)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Fatal("Accept error:", err)
        }

        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    buf := make([]byte, 1024)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            log.Println("Read error:", err)
            return
        }

        log.Printf("Received: %s", string(buf[:n]))

        // Echo the message back to the client
        _, err = conn.Write(buf[:n])
        if err != nil {
            log.Println("Write error:", err)
            return
        }
    }
}
```
