# FortiChat – Encrypted Client–Server Messaging System

---

## 1. Project Overview

### 1.1 Why
Secure communication is essential in modern networked systems.  
FortiChat demonstrates **secure client–server communication**, cryptography, and concurrency using low-level C++ networking.

### 1.2 What
FortiChat is a **terminal-based encrypted messaging system** in **C++**.  
It supports multiple clients connecting to a TCP server and demonstrates:

- Networking via Berkeley sockets  
- SHA-256 authentication  
- AES-256 and 3DES encryption  
- Multi-threaded server design  
- File-based persistence for users, bans, and logs  

### 1.3 How (High-Level)
- TCP client–server architecture  
- Thread-safe concurrency with POSIX threads  
- Encrypted message exchange using AES-256 / 3DES  
- Administrative moderation with logging  
- Streak-based user activity tracking  

---

## 2. Features

- 🔒 Encrypted client–server messaging  
- 👥 Multi-client support with threads  
- ✅ Secure user authentication  
- ⚖️ Admin moderation: ban, kick, restrict  
- 📝 Violation tracking & IP-based blocking  
- 🏆 Streak system & leaderboard  
- 📂 Persistent logging of users, bans, and actions  

---

## 3. Tech Stack

- **Language**: C++  
- **Networking**: Berkeley Sockets (TCP)  
- **Cryptography**: OpenSSL (SHA-256, AES-256, 3DES)  
- **Concurrency**: POSIX Threads  
- **Platform**: Linux / WSL  

---

## 4. Project Structure

```

FortiChat/
│── src/
│   ├── server.cpp
│   └── client.cpp
│── README.md
│── .gitignore

````

---

## 5. Setup & Usage

### 5.1 Prerequisites
- Linux or WSL  
- OpenSSL installed  
- g++ compiler with pthread support  

### 5.2 Compilation

**Server**
```bash
g++ src/server.cpp -o server -lssl -lcrypto -pthread
./server
````

**Client**

```bash
g++ src/client.cpp -o client -lssl -lcrypto
./client
```

> Note: Native Windows builds are not supported.

---

## 6. Major Components

### 6.1 Server Module (`server.cpp`)

**Responsibilities:**

* Handle multiple clients concurrently
* Authentication & session management
* Admin moderation (ban, kick, restrict)
* Persistent storage for bans and logs

**Admin Commands**

```
users          - List connected users
ban <user>     - Ban a user
unban <user>   - Remove ban
delete <user>  - Delete account
kick <user>    - Disconnect user
restricted     - Show banned users
violations     - Show violations
blocked        - Show blocked IPs
logs           - View logs
broadcast <m>  - Message all users
status         - Server status
help           - Show commands
exit           - Graceful shutdown
```

### 6.2 Client Module (`client.cpp`)

**Responsibilities:**

* Connect to server (`127.0.0.1:8080`)
* Handle secure authentication
* Send/receive encrypted messages
* Respond to server admin actions

**Client Commands**

```
help
broadcast <message>
private <message>
streak
leaderboard
rules
delete
exit
```

---

## 7. Security & Cryptography

### 7.1 SHA-256 Hashing

* Used for password hashing, identity verification, and data integrity
* **Workflow:** `Password → SHA-256 → Hash → Server Verification`

### 7.2 AES-256 Encryption (Primary)

* Encrypts messages, session tokens, and sensitive commands
* **Modes:** CBC or ECB
* Fast, secure, standard across OS

### 7.3 3DES Encryption (Fallback)

* Used if AES unavailable
* Pros: Simple, legacy compatibility
* Cons: Slower, lower security margin

---

## 8. Logging & Monitoring

* `admin_logs.txt` – Admin actions
* `violation_logs.txt` – User violations
* `restricted_users.txt` – Persistent bans
* `users.txt` – Credentials and streaks

> Logs include timestamps and identifiers for auditing.

---

## 9. Workflow / Execution

### 9.1 Server Start

* Loads stored data
* Prepares encryption context
* Listens for clients

### 9.2 Client Connect

* Establishes TCP connection
* Sends hashed credentials

### 9.3 Authentication

* Server validates credentials
* AES/3DES encrypted session begins

### 9.4 Messaging

* Exchange encrypted messages
* Maintain streak/time tracking

### 9.5 Session Termination

* Triggered by client command or server action
* Logs updated and resources cleaned

---

## 10. Learning Outcomes

* Secure socket programming
* Encryption and hashing techniques
* Multi-threaded network design
* Moderation and logging systems
* Security-aware C++ development

---

## 11. Limitations

* Terminal-based interface
* No TLS (custom encryption layer)
* File-based storage only
* Session keys stored in memory

---

## 12. Future Improvements

* Replace custom encryption with TLS
* Database-backed user storage
* RSA key exchange
* Qt/web GUI
* Message history persistence

---

## 13. Ethical & Legal Notice ⚠️

* For **educational and experimental purposes only**
* Controlled environment testing
* Misuse for unauthorized access is prohibited

---

## 14. Author & Contact

**Name**: Mohid Umer  
**Email**: [mohidumer112@gmail.com](mailto:mohidumer112@gmail.com)

---

## 15. License

* Released for educational purposes
* See repository license file for details

---

> FortiChat is a learning project for Linux based network programming and secure encryption solution. Feedback and collaboration are welcome.

---
