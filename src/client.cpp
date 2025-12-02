//-------------------------------//
//          Mohid Umer           //
//-------------------------------//
//     FortiChat Assignment      //
//-------------------------------//

//-------------------------------//
//           client.cpp          //
//-------------------------------//

#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <map>
#include <thread>
#include <atomic>
#include <signal.h>
using namespace std;

// Terminal Colors
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

// Global Variables
int sock;
const int maxSize = 50;
string current_user;
int user_streak = 0;
int encryption_type = 0; // 0=SHA256, 1=AES, 2=3DES
atomic<bool> connected{false};
atomic<bool> forced_disconnect{false};

// Encryption type names
const vector<string> enc_types = {"SHA256", "AES", "3DES"};

// Function to handle graceful exit
void cleanup(int signal) {
    if (connected) {
        cout << COLOR_YELLOW << "\n👋 Disconnecting from server..." << COLOR_RESET << endl;
        connected = false;
        close(sock);
        exit(0);
    }
}

// Function to hash the password with SHA-256 and salt
string hashPasswordSHA256(const char* password, const char* salt) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestUpdate(mdctx, salt, strlen(salt));
    EVP_DigestFinal_ex(mdctx, hash, &hashLength);
    EVP_MD_CTX_free(mdctx);

    char outputBuffer[65];
    for (unsigned int i = 0; i < hashLength; i++) {
        sprintf(&outputBuffer[i * 2], "%02x", hash[i]);
    }
    outputBuffer[64] = '\0';
    return string(outputBuffer);
}

// Function to encrypt with AES
string encryptAES(const char* password, const char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[128];
    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key, (unsigned char*)"0123456789abcdef");
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)password, strlen(password));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    char outputBuffer[256];
    for (int i = 0; i < ciphertext_len; i++) {
        sprintf(&outputBuffer[i * 2], "%02x", ciphertext[i]);
    }
    outputBuffer[ciphertext_len * 2] = '\0';
    return string(outputBuffer);
}

// Function to encrypt with 3DES (using EVP for OpenSSL 3.0 compatibility)
string encrypt3DES(const char* password, const char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[128];
    int len;
    int ciphertext_len;

    // Use 3DES in CBC mode
    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, 
                      (unsigned char*)key, (unsigned char*)"12345678");
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)password, strlen(password));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    char outputBuffer[256];
    for (int i = 0; i < ciphertext_len; i++) {
        sprintf(&outputBuffer[i * 2], "%02x", ciphertext[i]);
    }
    outputBuffer[ciphertext_len * 2] = '\0';
    return string(outputBuffer);
}

// Function to generate a random salt/key
void generateRandom(char* output, int length) {
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < length; ++i) {
        output[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    output[length] = '\0';
}

string encryptPassword(int type, const char* password, const char* salt_key) {
    switch(type) {
        case 0: return hashPasswordSHA256(password, salt_key);
        case 1: return encryptAES(password, salt_key);
        case 2: return encrypt3DES(password, salt_key);
        default: return hashPasswordSHA256(password, salt_key);
    }
}

void saveUser(const char* email, const char* username, const char* password, int enc_type) {
    ofstream outFile("users.txt", ios::app);
    if (outFile.is_open()) {
        char salt_key[32];
        generateRandom(salt_key, (enc_type == 0) ? 16 : 8);
        string encryptedPassword = encryptPassword(enc_type, password, salt_key);

        outFile << "email: " << email << ", username: " << username 
                << ", password: " << encryptedPassword << ", salt_key: " << salt_key 
                << ", enc_type: " << enc_type << ", streak: 0, last_login: 0\n";
        
        cout << COLOR_GREEN << COLOR_BOLD << "\n[SUCCESS] User registered with " << enc_types[enc_type] << " encryption!\n" << COLOR_RESET << endl;
        outFile.close();
    } else {
        cout << COLOR_RED << "[ERROR] Error opening users file.\n" << COLOR_RESET;
    }
}

bool checkCredentials(const char* inputUsername, const char* inputPassword) {
    ifstream inFile("users.txt");
    string line;

    while (getline(inFile, line)) {
        size_t usernamePos = line.find("username:");
        size_t passwordPos = line.find("password:");
        size_t saltPos = line.find("salt_key:");
        size_t typePos = line.find("enc_type:");
        size_t streakPos = line.find("streak:");

        if (usernamePos == string::npos || passwordPos == string::npos) continue;

        string storedUser = line.substr(usernamePos + 10, passwordPos - (usernamePos + 12));
        string storedPass = line.substr(passwordPos + 10, saltPos - (passwordPos + 12));
        string storedSalt = line.substr(saltPos + 10, typePos - (saltPos + 12));
        int storedType = stoi(line.substr(typePos + 10, streakPos - (typePos + 12)));

        if (storedUser == inputUsername) {
            string encryptedInput = encryptPassword(storedType, inputPassword, storedSalt.c_str());
            if (storedPass == encryptedInput) {
                current_user = inputUsername;
                encryption_type = storedType;
                
                // Extract streak (for display only, server will handle updates)
                size_t lastLoginPos = line.find("last_login:");
                if (streakPos != string::npos && lastLoginPos != string::npos) {
                    user_streak = stoi(line.substr(streakPos + 8, lastLoginPos - (streakPos + 9)));
                }
                
                inFile.close();
                return true;
            }
        }
    }
    inFile.close();
    return false;
}

void deleteAccount() {
    cout << COLOR_RED << "\n[WARNING] Are you sure you want to delete your account? (yes/no): " << COLOR_RESET;
    string confirmation;
    cin >> confirmation;
    
    if (confirmation == "yes" || confirmation == "y") {
        cout << COLOR_RED << "[CONFIRM] Type 'DELETE' to confirm permanent deletion: " << COLOR_RESET;
        cin >> confirmation;
        
        if (confirmation == "DELETE") {
            // Send delete command to server
            string msg = "DELETE_ACCOUNT " + current_user;
            send(sock, msg.c_str(), msg.length(), 0);
            cout << COLOR_GREEN << "[SUCCESS] Account deletion request sent.\n" << COLOR_RESET;
            forced_disconnect = true;
        } else {
            cout << COLOR_YELLOW << "[INFO] Account deletion cancelled.\n" << COLOR_RESET;
        }
    } else {
        cout << COLOR_YELLOW << "[INFO] Account deletion cancelled.\n" << COLOR_RESET;
    }
}

void create_socket() {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cout << COLOR_RED << "[ERROR] Error creating socket." << COLOR_RESET << endl;
        exit(1);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(8080);

    cout << COLOR_YELLOW << "[CONNECT] Connecting to server at 127.0.0.1:8080..." << COLOR_RESET << endl;
    
    if (connect(sock, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        cout << COLOR_RED << "[ERROR] Connection Failed! Server might be down." << COLOR_RESET << endl;
        exit(1);
    }
    
    connected = true;
    cout << COLOR_GREEN << "[SUCCESS] Connected to server successfully!" << COLOR_RESET << endl;
}

bool isValidEmail(const char* email) {
    string emailStr(email);
    return emailStr.find("@gmail.com") != string::npos;
}

void printWelcomeBanner() {
    cout << COLOR_BOLD << COLOR_CYAN;
    cout << "=========================================================\n";
    cout << "|                 SECUREC CHAT CLIENT                   |\n";
    cout << "|               Multi-User Secure System                |\n";
    cout << "|                   by Mohid Umer                       |\n";
    cout << "|                 Roll: 23i-2130                        |\n";
    cout << "=========================================================\n";
    cout << COLOR_RESET;
}

void showHelp() {
    cout << COLOR_BOLD << COLOR_BLUE << "\n======= AVAILABLE COMMANDS =======" << COLOR_RESET << endl;
    cout << COLOR_CYAN << "help" << COLOR_WHITE << " - Show this help message\n";
    cout << COLOR_CYAN << "broadcast <message>" << COLOR_WHITE << " - Send message to all users\n";
    cout << COLOR_CYAN << "private <message>" << COLOR_WHITE << " - Send private message to server\n";
    cout << COLOR_CYAN << "streak" << COLOR_WHITE << " - Show your current login streak\n";
    cout << COLOR_CYAN << "leaderboard" << COLOR_WHITE << " - Show top 5 users by streak\n";
    cout << COLOR_CYAN << "rules" << COLOR_WHITE << " - Show chat rules and guidelines\n";
    cout << COLOR_CYAN << "delete" << COLOR_WHITE << " - Delete your account\n";
    cout << COLOR_CYAN << "exit" << COLOR_WHITE << " - Exit the chat\n";
    cout << COLOR_BLUE << "=================================\n" << COLOR_RESET;
}

void handleServerShutdown() {
    cout << COLOR_RED << "\n╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                 SERVER SHUTDOWN                         ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    cout << "║ The server is shutting down for maintenance.            ║\n";
    cout << "║ Thank you for using SecureC Chat!                       ║\n";
    cout << "╚═════════════════════════════════════════════════════════╝\n" << COLOR_RESET;
    connected = false;
    forced_disconnect = true;
}

void handleKick() {
    cout << COLOR_RED << "\n╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                   YOU HAVE BEEN KICKED                  ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    cout << "║ You have been kicked from the server by an administrator║\n";
    cout << "╚═════════════════════════════════════════════════════════╝\n" << COLOR_RESET;
    connected = false;
    forced_disconnect = true;
}

void handleBan() {
    cout << COLOR_RED << "\n╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                   ACCESS DENIED                         ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    cout << "║          Your account has been BANNED due to            ║\n";
    cout << "║         violations of our community guidelines.         ║\n";
    cout << "║                                                         ║\n";
    cout << "║           You cannot join the chat until an             ║\n";
    cout << "║             administrator removes the ban.              ║\n";
    cout << "║                                                         ║\n";
    cout << "║        Review the rules using 'rules' command           ║\n";
    cout << "╚═════════════════════════════════════════════════════════╝\n" << COLOR_RESET;
    connected = false;
    forced_disconnect = true;
}

void handleAccountDeleted() {
    cout << COLOR_RED << "\n╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                   ACCOUNT DELETED                       ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    cout << "║ Your account has been permanently deleted.              ║\n";
    cout << "║ Thank you for using SecureC Chat!                       ║\n";
    cout << "╚═════════════════════════════════════════════════════════╝\n" << COLOR_RESET;
    connected = false;
    forced_disconnect = true;
}

void listenForMessages() {
    char buffer[2048];
    while (connected) {
        memset(buffer, 0, sizeof(buffer));
        int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        
        if (received > 0) {
            buffer[received] = '\0';
            string message(buffer);
            
            // Check for special server messages
            if (message.find("SERVER SHUTDOWN") != string::npos || 
                message.find("server is shutting down") != string::npos) {
                handleServerShutdown();
                break;
            } else if (message.find("YOU HAVE BEEN KICKED") != string::npos || 
                       message.find("kicked from the server") != string::npos) {
                handleKick();
                break;
            } else if (message.find("ACCOUNT DELETED") != string::npos || 
                       message.find("account has been permanently deleted") != string::npos) {
                handleAccountDeleted();
                break;
            } else if (message.find("ACCESS DENIED") != string::npos || 
                       message.find("account has been BANNED") != string::npos) {
                handleBan();
                break;
            }
            
            cout << "\r" << string(100, ' ') << "\r"; // Clear line
            cout << COLOR_MAGENTA << "[SERVER]\n" << COLOR_RESET << message << endl;
            
            if (connected && !forced_disconnect) {
                cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
            }
            
        } else if (received == 0) {
            // Server closed connection
            if (!forced_disconnect) {
                cout << COLOR_RED << "\n[ERROR] Server disconnected unexpectedly!\n" << COLOR_RESET;
            }
            connected = false;
            break;
        } else {
            // Error in recv
            if (connected && !forced_disconnect) {
                cout << COLOR_RED << "\n[ERROR] Connection lost!\n" << COLOR_RESET;
            }
            connected = false;
            break;
        }
    }
}

void chat() {
    char buf[1024];
    
    // Set up signal handlers for graceful exit
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    printWelcomeBanner();
    
    create_socket();
    
    int userOption;
    cout << COLOR_BOLD << COLOR_BLUE << "\n=== AUTHENTICATION MENU ===" << COLOR_RESET << endl;
    cout << COLOR_CYAN << "1. " << COLOR_WHITE << "Register New Account\n";
    cout << COLOR_CYAN << "2. " << COLOR_WHITE << "Login to Existing Account\n";
    cout << COLOR_BLUE << "Choose option: " << COLOR_RESET;
    cin >> userOption;
    cin.ignore();

    if (userOption == 1) {
        char email[maxSize], username[maxSize], password[maxSize];
        do {
            cout << COLOR_CYAN << "Email: " << COLOR_RESET;
            cin.getline(email, maxSize);
            if (!isValidEmail(email)) {
                cout << COLOR_RED << "Invalid email! Use @gmail.com\n" << COLOR_RESET;
            }
        } while (!isValidEmail(email));
        
        cout << COLOR_CYAN << "Username: " << COLOR_RESET;
        cin.getline(username, maxSize);
        cout << COLOR_CYAN << "Password: " << COLOR_RESET;
        cin.getline(password, maxSize);
        
        cout << COLOR_BOLD << COLOR_BLUE << "\n=== ENCRYPTION TYPE ===" << COLOR_RESET << endl;
        cout << COLOR_CYAN << "1. " << COLOR_WHITE << "SHA256 (Hashing)\n";
        cout << COLOR_CYAN << "2. " << COLOR_WHITE << "AES (Symmetric Encryption)\n";
        cout << COLOR_CYAN << "3. " << COLOR_WHITE << "3DES (Symmetric Encryption)\n";
        cout << COLOR_BLUE << "Choose encryption: " << COLOR_RESET;
        int enc_choice;
        cin >> enc_choice;
        cin.ignore();
        
        saveUser(email, username, password, enc_choice - 1);
        
        // Auto-login after registration
        current_user = username;
        encryption_type = enc_choice - 1;
        user_streak = 0;
        cout << COLOR_GREEN << "\n[SUCCESS] Auto-login as " << username << "! Streak: " << user_streak << COLOR_RESET << endl;
        string login_msg = "USER_LOGIN " + string(username);
        send(sock, login_msg.c_str(), login_msg.length(), 0);
        
    } else if (userOption == 2) {
        char username[maxSize], password[maxSize];
        cout << COLOR_CYAN << "Username: " << COLOR_RESET;
        cin.getline(username, maxSize);
        cout << COLOR_CYAN << "Password: " << COLOR_RESET;
        cin.getline(password, maxSize);

        if (checkCredentials(username, password)) {
            cout << COLOR_GREEN << "\n[SUCCESS] Welcome back " << username << "! Streak: " << user_streak << COLOR_RESET << endl;
            // Send login notification to server
            string login_msg = "USER_LOGIN " + string(username);
            send(sock, login_msg.c_str(), login_msg.length(), 0);
        } else {
            cout << COLOR_RED << "[ERROR] Login failed!\n" << COLOR_RESET;
            close(sock);
            exit(1);
        }
    } else {
        cout << COLOR_RED << "[ERROR] Invalid option!\n" << COLOR_RESET;
        close(sock);
        exit(1);
    }

    // Start message listening thread
    thread listener_thread(listenForMessages);
    listener_thread.detach();

    cout << COLOR_GREEN << "\n[CHAT] Session started! Type 'help' for commands.\n" << COLOR_RESET;
    showHelp();
    
    cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;

    while (connected) {
        string input;
        getline(cin, input);
        
        if (!connected || forced_disconnect) break;
        
        // Skip empty inputs
        if (input.empty()) {
            if (connected) {
                cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
            }
            continue;
        }
            
        if (input == "exit") {
            cout << COLOR_YELLOW << "👋 Goodbye!\n" << COLOR_RESET;
            break;
        } else if (input == "help") {
            showHelp();
            if (connected) {
                cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
            }
        } else if (input == "streak") {
            cout << COLOR_CYAN << "🔥 Your current streak: " << user_streak << " days" << COLOR_RESET << endl;
            if (connected) {
                cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
            }
        } else if (input == "leaderboard") {
            if (connected) {
                send(sock, "GET_LEADERBOARD", 15, 0);
            }
        } else if (input == "rules") {
            if (connected) {
                send(sock, "RULES", 5, 0);
            }
        } else if (input == "delete") {
            deleteAccount();
            if (connected && !forced_disconnect) {
                cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
            }
        } else if (input.find("broadcast ") == 0) {
            if (input.length() > 10) {
                if (connected) {
                    send(sock, input.c_str(), input.length(), 0);
                }
            } else {
                cout << COLOR_RED << "[ERROR] Broadcast message cannot be empty!\n" << COLOR_RESET;
                if (connected) {
                    cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
                }
            }
        } else if (input.find("private ") == 0) {
            if (input.length() > 8) {
                if (connected) {
                    send(sock, input.c_str(), input.length(), 0);
                }
            } else {
                cout << COLOR_RED << "[ERROR] Private message cannot be empty!\n" << COLOR_RESET;
                if (connected) {
                    cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
                }
            }
        } else {
            // Don't send anything for random inputs
            cout << COLOR_YELLOW << "[INFO] Use 'private <message>' to send message to server\n" << COLOR_RESET;
            if (connected) {
                cout << COLOR_BLUE << ">>> " << COLOR_RESET << flush;
            }
        }
    }

    connected = false;
    if (sock >= 0) {
        close(sock);
    }
    
    if (forced_disconnect) {
        cout << COLOR_YELLOW << "\nPress Enter to exit..." << COLOR_RESET;
        cin.ignore(); // Wait for user to see the message
    }
}

int main() {
    srand(static_cast<unsigned int>(time(0)));
    chat();
    return 0;
}