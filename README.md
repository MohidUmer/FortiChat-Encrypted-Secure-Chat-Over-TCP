# FortiChat – Encrypted Client–Server Messaging System

FortiChat is a **terminal-based encrypted communication system** written in **C++**, designed to simulate secure communication between a client and server over TCP.
It demonstrates key concepts of:

* **Socket programming** (Berkeley Sockets)
* **Symmetric and asymmetric encryption**
* **SHA-256 hashing for credential verification**
* **"AES-256" or "3DES" encryption for secure message transfer**
* **Multi-threaded server handling**
* **Session management & streak-based user activity**
* **Logging and input validation**

This project allows users to establish an encrypted session with a central server, authenticate securely, and exchange protected messages.

---

# 📌 Project Structure

```
FortiChat/
│── src/
│   ├── server.cpp
│   └── client.cpp
│── README.md
│── .gitignore
```

---

# 🛠️ Compilation Instructions

Compile using **g++** with OpenSSL support:

### **Compile & Run Server** (in one terminal)

g++ src/server.cpp -o server -lssl -lcrypto -pthread
./server

### **Compile & Run Client** (in another terminal)

g++ src/client.cpp -o client -lssl -lcrypto
./client

> **Note:**
> This system requires **Linux/WSL** because it uses POSIX threads, OpenSSL, and BSD sockets.

---

# Major Components
## ✔ Server Module (`server.cpp`)

The server handles:

* **Multi-client management** with thread-safe operations
* **Real-time administrative controls** with ban/kick/delete capabilities  
* **Advanced user moderation** with IP blocking and violation tracking
* **Secure authentication system** with multiple encryption options
* **Automatic content filtering** with bad word detection
* **Streak-based reward system** with leaderboard functionality
* **Comprehensive logging** for security and moderation

### Server Responsibilities:

* **Listens on TCP port 8080** for client connections
* **Manages concurrent clients** using detached threads
* **Administrative console** with real-time command processing
* **User restriction system** with persistent ban storage
* **Violation tracking** to identify repeat offenders
* **IP-based blocking** to prevent reconnect attacks
* **Broadcast messaging** to all connected clients
* **Automatic session cleanup** for disconnected clients
* **Streak calculation** based on login frequency
* **Real-time server status** monitoring

### Admin Commands Available:
```
users        - Show all connected users and IPs
ban <user>   - Ban a user from the server
unban <user> - Unban a user
delete <user> - Delete a user account permanently
kick <user>  - Kick a user from the server
restricted   - Show all banned users
violations   - Show users with violation counts
blocked      - Show blocked IP addresses
logs         - Show recent admin actions
broadcast <msg> - Send message to all users
status       - Show server status
help         - Show admin commands
exit         - Shutdown server gracefully
```

---

## ✔ Client Module (`client.cpp`)

The client handles:

* **Secure server connection** with automatic reconnection handling
* **Multiple encryption methods** (SHA256, AES, 3DES) for password protection
* **Real-time message reception** with dedicated listener thread
* **Graceful disconnection handling** for server actions (ban/kick/delete)
* **User authentication** with persistent credential storage
* **Interactive chat interface** with command system
* **Automatic response** to server administrative actions

### Client Responsibilities:

* **Establish TCP connection** to server at 127.0.0.1:8080
* **User registration/login** with email validation
* **Password encryption** using selected method (SHA256/AES/3DES)
* **Real-time message listening** in background thread
* **Command processing** for chat functionality
* **Account management** with self-deletion capability
* **Server action response** (automatic disconnect on ban/kick)
* **Session management** with proper cleanup
* **User interface** with colored terminal output

### Client Commands Available:
```
help        - Show help message
broadcast <message> - Send message to all users
private <message> - Send private message to server
streak      - Show current login streak
leaderboard - Show top 5 users by streak
rules       - Show chat rules and guidelines
delete      - Delete your account
exit        - Exit the chat
```

---

## 🔧 Technical Features

### Security & Moderation:
* **IP-based blocking** prevents reconnect attacks (5-minute blocks)
* **Violation counting** tracks user misbehavior patterns
* **Content filtering** automatically bans users for inappropriate language
* **Admin action logging** with timestamps and IP tracking
* **Persistent ban storage** across server restarts

### User Experience:
* **Streak system** rewards consistent usage with increasing points
* **Real-time leaderboard** shows top 5 users
* **Colored interface** with clear visual feedback
* **Automatic responses** to server administrative actions
* **Graceful error handling** for connection issues

### System Architecture:
* **Thread-safe operations** with mutex protection
* **Non-blocking admin console** for real-time moderation
* **Atomic variables** for thread communication
* **Proper resource cleanup** on all exit paths
* **Comprehensive file I/O** for data persistence

---

## 📊 Logging & Monitoring

The system maintains:
* **`admin_logs.txt`** - All administrative actions with timestamps
* **`violation_logs.txt`** - User violations and repeat offenses  
* **`restricted_users.txt`** - Persistent ban list
* **`users.txt`** - User credentials and streak data
* **Real-time console output** with color-coded status messages

This updated documentation reflects the current advanced moderation system, IP blocking capabilities, comprehensive logging, and real-time administrative controls implemented in your secure chat system.

---

# 🔐 Hashing & Encryption

FortiChat uses three core cryptographic mechanisms:

## 🔸 1. **SHA-256 Hashing**

Used for:

* password hashing
* identity validation
* integrity checking

*Hash Example Workflow:*
password → SHA256 → 64-character hash → sent to server
Server compares received hash with stored hash.

---

## 🔸 2. **AES-256 Encryption (Primary)**

AES is used to encrypt:

* chat messages
* session tokens
* sensitive commands

### Mode typically used:

* **AES-256 CBC** or **AES-256 ECB**

*Why AES?*
* Fast
* Secure
* Standard across all OS

---

## 🔸 3. **3DES Encryption (Fallback)**

Used if AES fails or is disabled.

Pros:

* Simple
* Compatible with older systems

Cons:

* Slower than AES
* Lower security margin

---

# 🔌 Socket Programming Details

The project uses **Berkeley Sockets (AF_INET, SOCK_STREAM)**.

### Server:

* `socket()`
* `bind()`
* `listen()`
* `accept()`
* `recv() / send()`
* `close()`

### Client:

* `socket()`
* `connect()`
* `send() / recv()`
* `close()`

All connections use **port-based TCP communication**.

---

# 🔁 Workflow / Execution

## 1. **Server Starts**

* Opens TCP port
* Loads/verifies credentials
* Prepares encryption keys
* Waits for clients

## 2. **Client Connects**

* Creates socket
* Connects via IP + port
* Sends username hashed with SHA-256

## 3. **Authentication**

* Server compares hash
* On success → encryption begins
* On failure → client rejected

## 4. **Encrypted Session Begins**

Client & server:

* Exchange AES session keys
* Encrypt message → send → decrypt
* Maintain streak/time

## 5. **Messaging Loop**

Client:

```
Encrypt → Send → Receive Response → Decrypt
```

Server:

```
Threaded handler → decrypt → process → encrypt → respond
```

## 6. **Session End**

Triggered by:

* Client command
* Timeout
* Interrupt signal

Server logs:

* user
* timestamp
* streak
* total messages
* ban/unban users
* restricted users

---

# ⚙️ Key Function Explanation

## 📁 server.cpp

Handles:

* Socket initialization
* Accepting clients
* Thread creation
* Hash validation
* AES encryption/decryption
* Logging

Workflow:
**listen() → accept() → handle_client_thread() → encrypt/decrypt → cleanup**

---

## 📁 client.cpp

Handles:

* User input
* SHA-256 hashing
* AES/3DES encryption
* Connection to server
* Displaying messages

Workflow:
**connect() → login → start AES → send encrypted messages → exit**

---

# ⭐ Pros & Cons

## ✅ Pros

* Secure (AES-256 + SHA-256)
* Clean client-server separation
* Supports multi-client threading
* Lightweight and portable
* Proper logging system
* Educational use of OpenSSL and sockets

## ❌ Cons / Limitations

* No GUI (terminal only)
* Requires Linux/WSL
* No persistent database for user credentials simple tst files only
* Session keys stored in memory
* No TLS—only custom encryption layer

---

# 🚨 Exception & Error Handling

The system safely handles:

* Socket creation failures
* Hash mismatches
* Decryption failures
* Invalid commands
* Broken pipe / disconnected clients
* OpenSSL errors

Server uses:

* `try/catch`
* `if (!socket) {...}`
* `ERR_print_errors_fp()`

Client uses:

* Input sanitization
* Connection retries
* Clean socket shutdown

---

# 📚 Future Improvements

* Add TLS/SSL instead of manual AES
* Add MySQL/PostgreSQL for user accounts
* Make a Qt or web-based GUI
* Implement RSA for key exchange
* Add message history storage

---

---

## 👨‍💻 About the Developer

**Name**: Mohid Umer  
**Email**: mohidumer112@gmail.com  

---

## 🤝 Contributing & Support

For bug reports, feature suggestions, or questions about **FortiChat**:

1. **Report Issues**: Include exact error messages and reproduction steps  
2. **Suggest Features**: Describe enhancement ideas with context and use cases  
3. **Ask Questions**: Reach out via email with specific technical questions  

**Contact**: mohidumer112@gmail.com  

---

## 📝 Changelog

### Version 1.0 (Current)
- ✨ Initial release of FortiChat  
- 🔒 Full end-to-end encryption for secure messaging  
- ✅ Multi-client support with authentication  
- 📁 File transfer support  
- 🎨 Color-coded console interface for easy readability  
- 💾 Local message history storage  
- 📚 Documentation included for all core features  

---

## 📞 Support & Contact

For issues, questions, or feedback about **FortiChat**:

**Email**: mohidumer112@gmail.com  
**Status**: Active Development  
**Last Updated**: December 16, 2025  

---

**Thank you for using FortiChat!** 🎉

