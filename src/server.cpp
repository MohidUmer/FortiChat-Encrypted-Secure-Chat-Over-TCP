//-------------------------------//
//          Mohid Umer           //
//-------------------------------//
//     FortiChat Assignment      //
//-------------------------------//

//-------------------------------//
//           server.cpp          //
//-------------------------------//

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <arpa/inet.h>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
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

struct ClientInfo {
    int socket;
    string username;
    int streak;
    string ip;
};

vector<ClientInfo> clients;
map<string, int> user_streaks; // username -> streak
map<string, time_t> last_logins; // username -> last login time
map<string, bool> restricted_users; // username -> restricted status
map<string, string> user_ips; // username -> IP address
map<string, int> violation_count; // username -> number of violations
map<string, time_t> blocked_ips; // ip -> block until time
mutex clients_mutex;
mutex users_mutex;
mutex ips_mutex;
atomic<bool> server_running{true};

// Streak configuration (1 minute for testing, change to 12-24 hours for production)
const int STREAK_WINDOW = 60; // 1 minute in seconds
const int IP_BLOCK_TIME = 300; // 5 minutes block for banned users

// Bad words list for content filtering
vector<string> bad_words = {
    "fuck", "shit", "asshole", "bitch", "bastard", "damn", "hell", 
    "cunt", "piss", "dick", "cock", "pussy", "whore", "slut"
};

string getCurrentTime() {
    time_t now = time(0);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

bool isIpBlocked(const string& ip) {
    lock_guard<mutex> lock(ips_mutex);
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end()) {
        if (time(0) < it->second) {
            return true; // Still blocked
        } else {
            blocked_ips.erase(it); // Block expired
            return false;
        }
    }
    return false;
}

void blockIp(const string& ip) {
    lock_guard<mutex> lock(ips_mutex);
    blocked_ips[ip] = time(0) + IP_BLOCK_TIME;
}

void logAdminAction(const string& action, const string& username, const string& admin = "SYSTEM") {
    ofstream logFile("admin_logs.txt", ios::app);
    if (logFile.is_open()) {
        logFile << "[" << getCurrentTime() << "] " << action << " - User: " << username 
                << " - By: " << admin << " - IP: " << (user_ips.count(username) ? user_ips[username] : "Unknown") << endl;
        logFile.close();
    }
    
    // Also log violations separately
    if (action.find("BAN") != string::npos || action.find("RESTRICT") != string::npos) {
        ofstream violationFile("violation_logs.txt", ios::app);
        if (violationFile.is_open()) {
            violationFile << "[" << getCurrentTime() << "] " << action << " - User: " << username 
                         << " - Total Violations: " << violation_count[username] 
                         << " - IP: " << (user_ips.count(username) ? user_ips[username] : "Unknown") << endl;
            violationFile.close();
        }
    }
}

void printWelcomeBanner() {
    cout << COLOR_BOLD << COLOR_CYAN;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                  SECURE CHAT SERVER                     ║\n";
    cout << "║               Multi-Client Secure System                ║\n";
    cout << "║                   by Mohid Umer                         ║\n";
    cout << "║                 Roll: 23i-2130                          ║\n";
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void printServerStatus(int connected_clients) {
    cout << COLOR_BOLD << COLOR_GREEN;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                     SERVER STATUS                       ║\n";
    cout << "║  Connected Clients: " << setw(35) << connected_clients << " ║\n";
    cout << "║  Active Users:   " << setw(38) << clients.size() << " ║\n";
    cout << "║  Server Time:   " << setw(39) << getCurrentTime() << " ║\n";
    cout << "║  Restricted Users:   " << setw(34) << restricted_users.size() << " ║\n";
    cout << "║  Total Violations:   " << setw(34) << violation_count.size() << " ║\n";
    cout << "║  Blocked IPs:      " << setw(36) << blocked_ips.size() << " ║\n";
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void showAdminHelp() {
    cout << COLOR_BOLD << COLOR_YELLOW;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                    ADMIN COMMANDS                       ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    cout << "║ " << COLOR_CYAN << "users" << COLOR_YELLOW << "             - Show all connected users and IP     ║\n";
    cout << "║ " << COLOR_CYAN << "ban <user>" << COLOR_YELLOW << "        - Ban a user from the server          ║\n";
    cout << "║ " << COLOR_CYAN << "unban <user>" << COLOR_YELLOW << "      - Unban a user                        ║\n";
    cout << "║ " << COLOR_CYAN << "delete <user>" << COLOR_YELLOW << "     - Delete a user account               ║\n";
    cout << "║ " << COLOR_CYAN << "restricted" << COLOR_YELLOW << "        - Show all restricted users           ║\n";
    cout << "║ " << COLOR_CYAN << "kick <user>" << COLOR_YELLOW << "       - Kick a user from the server         ║\n";
    cout << "║ " << COLOR_CYAN << "broadcast <msg>" << COLOR_YELLOW << "   - Send message to all users           ║\n";
    cout << "║ " << COLOR_CYAN << "violations" << COLOR_YELLOW << "        - Show users with violations          ║\n";
    cout << "║ " << COLOR_CYAN << "logs" << COLOR_YELLOW << "              - Show recent admin logs              ║\n";
    cout << "║ " << COLOR_CYAN << "blocked" << COLOR_YELLOW << "           - Show blocked IPs                    ║\n";
    cout << "║ " << COLOR_CYAN << "status" << COLOR_YELLOW << "            - Show server status                  ║\n";
    cout << "║ " << COLOR_CYAN << "help" << COLOR_YELLOW << "              - Show this help menu                 ║\n";
    cout << "║ " << COLOR_CYAN << "exit" << COLOR_YELLOW << "              - Shutdown the server                 ║\n";
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void loadUserData() {
    lock_guard<mutex> lock(users_mutex);
    ifstream inFile("users.txt");
    string line;
    user_streaks.clear();
    last_logins.clear();
    restricted_users.clear();
    violation_count.clear();
    
    // Load restricted users from separate file
    ifstream restrictFile("restricted_users.txt");
    string restricted_user;
    while (getline(restrictFile, restricted_user)) {
        if (!restricted_user.empty()) {
            restricted_users[restricted_user] = true;
        }
    }
    restrictFile.close();
    
    // Load violation counts
    ifstream violationFile("violation_logs.txt");
    string violation_line;
    while (getline(violationFile, violation_line)) {
        size_t userPos = violation_line.find("User: ");
        if (userPos != string::npos) {
            string username = violation_line.substr(userPos + 6);
            username = username.substr(0, username.find(" "));
            violation_count[username]++;
        }
    }
    violationFile.close();
    
    while (getline(inFile, line)) {
        size_t userPos = line.find("username:");
        size_t streakPos = line.find("streak:");
        size_t lastLoginPos = line.find("last_login:");
        
        if (userPos != string::npos && streakPos != string::npos && lastLoginPos != string::npos) {
            string username = line.substr(userPos + 10, line.find(',', userPos) - (userPos + 10));
            int streak = stoi(line.substr(streakPos + 8, lastLoginPos - (streakPos + 9)));
            time_t last_login = stol(line.substr(lastLoginPos + 12));
            
            user_streaks[username] = streak;
            last_logins[username] = last_login;
        }
    }
    inFile.close();
}

void updateUserStreak(const string& username, int new_streak) {
    lock_guard<mutex> lock(users_mutex);
    user_streaks[username] = new_streak;
    last_logins[username] = time(0);
    
    ifstream inFile("users.txt");
    vector<string> lines;
    string line;
    
    while (getline(inFile, line)) {
        size_t userPos = line.find("username:");
        if (userPos != string::npos) {
            string current_user = line.substr(userPos + 10, line.find(',', userPos) - (userPos + 10));
            if (current_user == username) {
                size_t streakPos = line.find("streak:");
                size_t lastLoginPos = line.find("last_login:");
                if (streakPos != string::npos && lastLoginPos != string::npos) {
                    line = line.substr(0, streakPos + 8) + to_string(new_streak) + 
                           ", last_login: " + to_string(time(0));
                }
            }
        }
        lines.push_back(line);
    }
    inFile.close();
    
    ofstream outFile("users.txt");
    for (const auto& l : lines) {
        outFile << l << '\n';
    }
    outFile.close();
}

void restrictUser(const string& username, const string& admin = "SYSTEM") {
    lock_guard<mutex> lock(users_mutex);
    restricted_users[username] = true;
    violation_count[username]++;
    
    // Block the IP if known
    if (user_ips.count(username)) {
        blockIp(user_ips[username]);
    }
    
    ofstream restrictFile("restricted_users.txt", ios::app);
    restrictFile << username << '\n';
    restrictFile.close();
    
    cout << COLOR_RED << "[ADMIN] User banned: " << username << " (Violations: " << violation_count[username] << ")" << COLOR_RESET << endl;
    logAdminAction("BAN", username, admin);
}

void unrestrictUser(const string& username, const string& admin = "SYSTEM") {
    lock_guard<mutex> lock(users_mutex);
    restricted_users.erase(username);
    
    ifstream inFile("restricted_users.txt");
    vector<string> lines;
    string line;
    
    while (getline(inFile, line)) {
        if (line != username) {
            lines.push_back(line);
        }
    }
    inFile.close();
    
    ofstream outFile("restricted_users.txt");
    for (const auto& l : lines) {
        outFile << l << '\n';
    }
    outFile.close();
    
    cout << COLOR_GREEN << "[ADMIN] User unbanned: " << username << COLOR_RESET << endl;
    logAdminAction("UNBAN", username, admin);
}

bool isUserRestricted(const string& username) {
    lock_guard<mutex> lock(users_mutex);
    return restricted_users.find(username) != restricted_users.end();
}

bool containsBadWords(const string& message) {
    string lower_message = message;
    transform(lower_message.begin(), lower_message.end(), lower_message.begin(), ::tolower);
    
    for (const auto& word : bad_words) {
        if (lower_message.find(word) != string::npos) {
            return true;
        }
    }
    return false;
}

int calculateNewStreak(const string& username) {
    time_t current_time = time(0);
    time_t last_login = last_logins[username];
    int current_streak = user_streaks[username];
    
    if (last_login == 0 || current_streak == 0) {
        return 5;
    }
    
    double time_diff = difftime(current_time, last_login);
    
    if (time_diff <= STREAK_WINDOW) {
        if (current_streak < 10) return current_streak + 5;
        else if (current_streak < 20) return current_streak + 10;
        else if (current_streak < 30) return current_streak + 15;
        else return current_streak + 20;
    } else {
        return 5;
    }
}

void deleteUserAccount(const string& username, const string& admin = "SYSTEM") {
    lock_guard<mutex> lock(users_mutex);
    ifstream inFile("users.txt");
    vector<string> lines;
    string line;
    bool found = false;
    
    while (getline(inFile, line)) {
        size_t userPos = line.find("username:");
        if (userPos != string::npos) {
            string current_user = line.substr(userPos + 10, line.find(',', userPos) - (userPos + 10));
            if (current_user != username) {
                lines.push_back(line);
            } else {
                found = true;
            }
        } else {
            lines.push_back(line);
        }
    }
    inFile.close();
    
    if (found) {
        ofstream outFile("users.txt");
        for (const auto& l : lines) {
            outFile << l << '\n';
        }
        outFile.close();
        user_streaks.erase(username);
        last_logins.erase(username);
        restricted_users.erase(username);
        
        // Block the IP to prevent immediate reconnection
        if (user_ips.count(username)) {
            blockIp(user_ips[username]);
        }
        
        cout << COLOR_GREEN << "[ADMIN] Deleted user: " << username << COLOR_RESET << endl;
        logAdminAction("DELETE_ACCOUNT", username, admin);
    } else {
        cout << COLOR_RED << "[ADMIN] User not found: " << username << COLOR_RESET << endl;
    }
}

void broadcastMessage(const string& message, int exclude_socket = -1) {
    lock_guard<mutex> lock(clients_mutex);
    for (const auto& client : clients) {
        if (client.socket != exclude_socket && client.username != "Unknown") {
            send(client.socket, message.c_str(), message.length(), 0);
        }
    }
}

void sendToClient(int socket, const string& message) {
    send(socket, message.c_str(), message.length(), 0);
}

void kickUser(const string& username, const string& admin = "SYSTEM") {
    lock_guard<mutex> lock(clients_mutex);
    for (auto it = clients.begin(); it != clients.end(); ) {
        if (it->username == username) {
            string kick_msg = string(COLOR_RED) + 
                "╔═════════════════════════════════════════════════════════╗\n" +
                "║                   YOU HAVE BEEN KICKED                  ║\n" +
                "╠═════════════════════════════════════════════════════════╣\n" +
                "║ You have been kicked from the server by an administrator║\n" +
                "╚═════════════════════════════════════════════════════════╝\n" + COLOR_RESET;
            
            sendToClient(it->socket, kick_msg);
            close(it->socket);
            it = clients.erase(it);
            cout << COLOR_RED << "[ADMIN] Kicked user: " << username << COLOR_RESET << endl;
            logAdminAction("KICK", username, admin);
            
            string broadcast_kick = string(COLOR_RED) + "🚫 [ADMIN] " + username + " has been kicked from the server!" + COLOR_RESET;
            broadcastMessage(broadcast_kick);
            break;
        } else {
            ++it;
        }
    }
}

void showConnectedUsers() {
    lock_guard<mutex> lock(clients_mutex);
    cout << COLOR_BOLD << COLOR_CYAN;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                 CONNECTED USERS                         ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    
    if (clients.empty()) {
        cout << "║                 No users connected                      ║\n";
    } else {
        for (const auto& client : clients) {
            string status = isUserRestricted(client.username) ? " [BANNED]" : "";
            cout << "║ " << setw(20) << left << client.username 
                 << " - " << setw(15) << client.ip 
                 << " - Streak: " << setw(4) << client.streak << status << "   ║\n";
        }
    }
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void showRestrictedUsers() {
    lock_guard<mutex> lock(users_mutex);
    cout << COLOR_BOLD << COLOR_RED;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                      BANNED USERS                       ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    
    if (restricted_users.empty()) {
        cout << "║                     No banned users                     ║\n";
    } else {
        for (const auto& user : restricted_users) {
            cout << "║ " << setw(20) << left << user.first 
                 << " - Violations: " << setw(3) << violation_count[user.first] << "                  ║\n";
        }
    }
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void showViolations() {
    lock_guard<mutex> lock(users_mutex);
    cout << COLOR_BOLD << COLOR_MAGENTA;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                     USER VIOLATIONS                     ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    
    if (violation_count.empty()) {
        cout << "║              No violations recorded                 ║\n";
    } else {
        vector<pair<string, int>> violations(violation_count.begin(), violation_count.end());
        sort(violations.begin(), violations.end(), 
             [](const pair<string, int>& a, const pair<string, int>& b) {
                 return a.second > b.second;
             });
        
        for (const auto& v : violations) {
            string status = restricted_users.count(v.first) ? " [BANNED]" : " [ACTIVE]";
            cout << "║ " << setw(20) << left << v.first 
                 << " - Violations: " << setw(3) << v.second << status << "         ║\n";
        }
    }
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void showBlockedIPs() {
    lock_guard<mutex> lock(ips_mutex);
    cout << COLOR_BOLD << COLOR_RED;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                   BLOCKED IP ADDRESSES                  ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    
    if (blocked_ips.empty()) {
        cout << "║                No IPs currently blocked                 ║\n";
    } else {
        time_t now = time(0);
        for (const auto& ip_block : blocked_ips) {
            int time_left = ip_block.second - now;
            if (time_left > 0) {
                cout << "║ " << setw(20) << left << ip_block.first 
                     << " - Blocked for: " << setw(4) << time_left << " seconds ║\n";
            }
        }
    }
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void showAdminLogs() {
    cout << COLOR_BOLD << COLOR_YELLOW;
    cout << "╔═════════════════════════════════════════════════════════╗\n";
    cout << "║                    RECENT ADMIN LOGS                    ║\n";
    cout << "╠═════════════════════════════════════════════════════════╣\n";
    
    ifstream logFile("admin_logs.txt");
    string line;
    vector<string> lines;
    
    while (getline(logFile, line)) {
        lines.push_back(line);
    }
    logFile.close();
    
    if (lines.empty()) {
        cout << "║              No admin logs found                    ║\n";
    } else {
        int start = max(0, (int)lines.size() - 10);
        for (int i = start; i < lines.size(); i++) {
            cout << "║ " << setw(55) << left << lines[i].substr(0, 55) << " ║\n";
        }
    }
    cout << "╚═════════════════════════════════════════════════════════╝\n";
    cout << COLOR_RESET;
}

void showLeaderboard(int client_socket) {
    lock_guard<mutex> lock(users_mutex);
    vector<pair<string, int>> ranked_users(user_streaks.begin(), user_streaks.end());
    sort(ranked_users.begin(), ranked_users.end(), 
         [](const pair<string, int>& a, const pair<string, int>& b) {
             return a.second > b.second;
         });
    
    stringstream ss;
    ss << COLOR_CYAN << "╔═════════════════════════════════════════════════════════╗\n";
    ss << "║                    LEADERBOARD                          ║\n";
    ss << "╠═════════════════════════════════════════════════════════╣\n";
    for (int i = 0; i < min(5, (int)ranked_users.size()); i++) {
        string status = restricted_users.count(ranked_users[i].first) ? " [BANNED]" : "";
        ss << "║ " << setw(2) << i+1 << ". " << setw(15) << left << ranked_users[i].first 
           << status << " - Streak: " << setw(6) << ranked_users[i].second << "                  ║\n";
    }
    ss << "╚═════════════════════════════════════════════════════════╝\n" << COLOR_RESET;
    sendToClient(client_socket, ss.str());
}

void showRules(int client_socket) {
    stringstream ss;
    ss << COLOR_BOLD << COLOR_YELLOW;
    ss << "╔═════════════════════════════════════════════════════════╗\n";
    ss << "║                     CHAT RULES                          ║\n";
    ss << "╠═════════════════════════════════════════════════════════╣\n";
    ss << "║ 1. No offensive language or hate speech                 ║\n";
    ss << "║ 2. Respect all users and their opinions                 ║\n";
    ss << "║ 3. No spamming or flooding the chat                     ║\n";
    ss << "║ 4. Keep conversations appropriate and friendly          ║\n";
    ss << "║ 5. No sharing of personal information                   ║\n";
    ss << "║ 6. Follow administrator instructions                    ║\n";
    ss << "║                                                         ║\n";
    ss << "║             VIOLATIONS WILL RESULT IN:                  ║\n";
    ss << "║                                                         ║\n";
    ss << "║ • Immediate account ban                                 ║\n";
    ss << "║ • Permanent ban for severe cases                        ║\n";
    ss << "║ • Account deletion for repeated offenses                ║\n";
    ss << "║                                                         ║\n";
    ss << "║  Use 'broadcast' for public messages                    ║\n";
    ss << "║  Use 'private' for server-only messages                 ║\n";
    ss << "╚═════════════════════════════════════════════════════════╝\n";
    ss << COLOR_RESET;
    sendToClient(client_socket, ss.str());
}

void processAdminCommand(const string& command) {
    if (command.find("ban ") == 0) {
        string username = command.substr(4);
        if (!username.empty()) {
            restrictUser(username, "ADMIN");
            kickUser(username, "ADMIN");
        } else {
            cout << COLOR_RED << "[ADMIN] Usage: ban <username>\n" << COLOR_RESET;
        }
    } else if (command.find("unban ") == 0) {
        string username = command.substr(6);
        if (!username.empty()) {
            unrestrictUser(username, "ADMIN");
        } else {
            cout << COLOR_RED << "[ADMIN] Usage: unban <username>\n" << COLOR_RESET;
        }
    } else if (command.find("delete ") == 0) {
        string username = command.substr(7);
        if (!username.empty()) {
            deleteUserAccount(username, "ADMIN");
            kickUser(username, "ADMIN");
        } else {
            cout << COLOR_RED << "[ADMIN] Usage: delete <username>\n" << COLOR_RESET;
        }
    } else if (command.find("kick ") == 0) {
        string username = command.substr(5);
        if (!username.empty()) {
            kickUser(username, "ADMIN");
        } else {
            cout << COLOR_RED << "[ADMIN] Usage: kick <username>\n" << COLOR_RESET;
        }
    } else if (command.find("broadcast ") == 0) {
        string message = command.substr(10);
        if (!message.empty()) {
            string admin_msg = string(COLOR_MAGENTA) + "📢 [ADMIN BROADCAST] " + message + COLOR_RESET;
            broadcastMessage(admin_msg);
            cout << COLOR_GREEN << "[ADMIN] Message broadcasted to all users\n" << COLOR_RESET;
            logAdminAction("BROADCAST", "ALL_USERS", "ADMIN");
        } else {
            cout << COLOR_RED << "[ADMIN] Usage: broadcast <message>\n" << COLOR_RESET;
        }
    } else if (command == "users") {
        showConnectedUsers();
    } else if (command == "restricted") {
        showRestrictedUsers();
    } else if (command == "violations") {
        showViolations();
    } else if (command == "blocked") {
        showBlockedIPs();
    } else if (command == "logs") {
        showAdminLogs();
    } else if (command == "status") {
        printServerStatus(clients.size());
    } else if (command == "help") {
        showAdminHelp();
    } else if (command == "exit") {
        cout << COLOR_RED << "[ADMIN] Shutting down server...\n" << COLOR_RESET;
        server_running = false;
        
        string shutdown_msg = string(COLOR_RED) + 
            "╔═════════════════════════════════════════════════════════╗\n" +
            "║                 SERVER SHUTDOWN                         ║\n" +
            "╠═════════════════════════════════════════════════════════╣\n" +
            "║ The server is shutting down for maintenance.            ║\n" +
            "║ Thank you for using SecureC Chat!                       ║\n" +
            "╚═════════════════════════════════════════════════════════╝\n" + COLOR_RESET;
        
        broadcastMessage(shutdown_msg);
        
        lock_guard<mutex> lock(clients_mutex);
        for (const auto& client : clients) {
            close(client.socket);
        }
        clients.clear();
    } else {
        cout << COLOR_RED << "[ADMIN] Unknown command. Type 'help' for available commands.\n" << COLOR_RESET;
    }
}

void handleAdminCommands() {
    string command;
    
    cout << COLOR_BOLD << COLOR_MAGENTA << "\n🔧 ADMIN CONSOLE ACTIVATED - Type 'help' for commands\n" << COLOR_RESET;
    showAdminHelp();
    
    while (server_running) {
        cout << COLOR_BOLD << COLOR_RED << "ADMIN> " << COLOR_RESET;
        getline(cin, command);
        
        if (command.empty()) continue;
        
        processAdminCommand(command);
        
        if (!server_running) break;
    }
}

void handleClient(int client_socket) {
    char buffer[1024];
    string client_username = "Unknown";
    string client_ip = "Unknown";
    
    // Get client IP address
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    client_ip = string(inet_ntoa(client_addr.sin_addr));
    
    // Check if IP is blocked
    if (isIpBlocked(client_ip)) {
        cout << COLOR_RED << "[BLOCKED] Connection from blocked IP: " << client_ip << COLOR_RESET << endl;
        close(client_socket);
        return;
    }
    
    cout << COLOR_GREEN << "[CONNECT] New client connected from " << client_ip << COLOR_RESET << endl;
    
    // Send welcome message
    string welcome_msg = string(COLOR_CYAN) + 
        "╔═════════════════════════════════════════════════════════╗\n" +
        "║                 WELCOME TO SECUREC CHAT                 ║\n" +
        "║           Multi-Client Secure System                    ║\n" +
        "╚═════════════════════════════════════════════════════════╝\n" +
        "Type 'help' for available commands\n" + COLOR_RESET;
    sendToClient(client_socket, welcome_msg);
    
    while (server_running) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) {
            cout << COLOR_YELLOW << "[DISCONNECT] Client disconnected: " << client_username << " (" << client_ip << ")" << COLOR_RESET << endl;
            
            if (client_username != "Unknown") {
                string leave_msg = string(COLOR_RED) + "👋 [SYSTEM] " + client_username + " left the chat!" + COLOR_RESET;
                broadcastMessage(leave_msg, client_socket);
                
                lock_guard<mutex> lock(clients_mutex);
                clients.erase(remove_if(clients.begin(), clients.end(), 
                    [client_socket](const ClientInfo& c) { return c.socket == client_socket; }), 
                    clients.end());
                
                printServerStatus(clients.size());
            }
            break;
        }
        
        buffer[bytes_received] = '\0';
        string message(buffer);
        
        cout << COLOR_BLUE << "[CLIENT " << client_username << "][" << client_ip << "] " << COLOR_WHITE << message << COLOR_RESET << endl;
        
        if (message.find("USER_LOGIN ") == 0) {
            client_username = message.substr(11);
            user_ips[client_username] = client_ip;
            
            if (isUserRestricted(client_username)) {
                string restriction_msg = string(COLOR_RED) + 
                    "╔═════════════════════════════════════════════════════════╗\n" +
                    "║                     ACCESS DENIED                       ║\n" +
                    "╠═════════════════════════════════════════════════════════╣\n" +
                    "║          Your account has been BANNED due to            ║\n" +
                    "║        violations of our community guidelines.          ║\n" +
                    "║                                                         ║\n" +
                    "║          You cannot join the chat until an              ║\n" +
                    "║           administrator removes the ban.                ║\n" +
                    "║                                                         ║\n" +
                    "║        Review the rules using 'rules' command           ║\n" +
                    "╚═════════════════════════════════════════════════════════╝\n" + COLOR_RESET;
                sendToClient(client_socket, restriction_msg);
                cout << COLOR_RED << "[BAN] Banned user attempted login: " << client_username << " (" << client_ip << ")" << COLOR_RESET << endl;
                logAdminAction("BANNED_LOGIN_ATTEMPT", client_username, "SYSTEM");
                
                // Block IP to prevent repeated connection attempts
                blockIp(client_ip);
                close(client_socket);
                return;
            }
            
            cout << COLOR_GREEN << "[LOGIN] User logged in: " << client_username << " (" << client_ip << ")" << COLOR_RESET << endl;
            
            int new_streak = calculateNewStreak(client_username);
            updateUserStreak(client_username, new_streak);
            
            ClientInfo new_client;
            new_client.socket = client_socket;
            new_client.username = client_username;
            new_client.streak = new_streak;
            new_client.ip = client_ip;
            
            {
                lock_guard<mutex> lock(clients_mutex);
                clients.push_back(new_client);
            }
            
            stringstream welcome_user;
            welcome_user << COLOR_GREEN;
            welcome_user << "╔═════════════════════════════════════════════════════════╗\n";
            welcome_user << "║                     LOGIN SUCCESSFUL                    ║\n";
            welcome_user << "╠═════════════════════════════════════════════════════════╣\n";
            welcome_user << "║ Welcome back, " << setw(38) << left << client_username << "    ║\n";
            welcome_user << "║ Current Streak: " << setw(36) << new_streak << "    ║\n";
            welcome_user << "║ Active Users: " << setw(38) << clients.size() << "    ║\n";
            welcome_user << "╚═════════════════════════════════════════════════════════╝\n";
            welcome_user << COLOR_RESET;
            sendToClient(client_socket, welcome_user.str());
            
            string login_msg = string(COLOR_GREEN) + "🎉 [SYSTEM] " + client_username + " joined the chat! (Streak: " + to_string(new_streak) + ", Total: " + to_string(clients.size()) + " users)" + COLOR_RESET;
            broadcastMessage(login_msg, client_socket);
            
            if (new_streak >= 20) {
                string streak_msg = string(COLOR_YELLOW) + "🔥 [ACHIEVEMENT] " + client_username + " has an impressive streak of " + to_string(new_streak) + " days!" + COLOR_RESET;
                broadcastMessage(streak_msg, client_socket);
            }
            
            printServerStatus(clients.size());
            
        } else if (message == "GET_LEADERBOARD") {
            showLeaderboard(client_socket);
            
        } else if (message == "RULES" || message == "rules") {
            showRules(client_socket);
            
        } else if (message.find("DELETE_ACCOUNT ") == 0) {
            string target_user = message.substr(15);
            if (target_user == client_username) {
                deleteUserAccount(client_username, "SELF");
                string response = string(COLOR_RED) + 
                    "╔═════════════════════════════════════════════════════════╗\n" +
                    "║                   ACCOUNT DELETED                       ║\n" +
                    "╠═════════════════════════════════════════════════════════╣\n" +
                    "║ Your account has been permanently deleted.              ║\n" +
                    "║ Thank you for using SecureC Chat!                       ║\n" +
                    "╚═════════════════════════════════════════════════════════╝\n" + COLOR_RESET;
                sendToClient(client_socket, response);
                
                string delete_msg = string(COLOR_RED) + "🗑️ [SYSTEM] " + client_username + " deleted their account!" + COLOR_RESET;
                broadcastMessage(delete_msg, client_socket);
                
                // Close connection after account deletion
                close(client_socket);
                return;
            }
            
        } else if (message.find("broadcast ") == 0) {
            string broadcast_content = message.substr(10);
            
            if (containsBadWords(broadcast_content)) {
                string warning_msg = string(COLOR_RED) + 
                    "🚨 [WARNING] Your message contains inappropriate language!\n" +
                    "Repeated violations will result in account ban or deletion!" + COLOR_RESET;
                sendToClient(client_socket, warning_msg);
                
                restrictUser(client_username, "AUTO_MOD");
                string restriction_msg = string(COLOR_RED) + 
                    "❌ [SYSTEM] You have been BANNED for using inappropriate language!\n" +
                    "You can no longer join the chat." + COLOR_RESET;
                sendToClient(client_socket, restriction_msg);
                
                string broadcast_ban = string(COLOR_RED) + "🚫 [ADMIN] " + client_username + " has been banned for inappropriate behavior!" + COLOR_RESET;
                broadcastMessage(broadcast_ban, client_socket);
                
                cout << COLOR_RED << "[BAN] User banned for bad language: " << client_username << " (" << client_ip << ")" << COLOR_RESET << endl;
                
                // Close connection after ban
                close(client_socket);
                return;
            }
            
            if (!broadcast_content.empty()) {
                string broadcast_msg = string(COLOR_CYAN) + "📢 [BROADCAST] " + client_username + ": " + broadcast_content + COLOR_RESET;
                broadcastMessage(broadcast_msg);
                cout << COLOR_MAGENTA << "[BROADCAST] " << client_username << ": " << broadcast_content << COLOR_RESET << endl;
                sendToClient(client_socket, "✅ Message broadcasted to all users");
            } else {
                sendToClient(client_socket, "❌ Broadcast message cannot be empty!");
            }
            
        } else if (message.find("private ") == 0) {
            string private_content = message.substr(8);
            if (!private_content.empty()) {
                string private_msg = string(COLOR_MAGENTA) + "🔒 [PRIVATE] " + client_username + " to Server: " + private_content + COLOR_RESET;
                sendToClient(client_socket, "✅ Server: Message received privately");
                cout << private_msg << endl;
            } else {
                sendToClient(client_socket, "❌ Private message cannot be empty!");
            }
            
        } else if (message == "help") {
            string help_msg = string(COLOR_BOLD) + COLOR_BLUE +
                "╔═════════════════════════════════════════════════════════╗\n" +
                "║                     AVAILABLE COMMANDS                  ║\n" +
                "╠═════════════════════════════════════════════════════════╣\n" +
                "║ help        - Show this help message                    ║\n" +
                "║ broadcast   - Send message to all users                 ║\n" +
                "║ private     - Send private message to server            ║\n" +
                "║ streak      - Show your current login streak            ║\n" +
                "║ leaderboard - Show top 5 users by streak                ║\n" +
                "║ rules       - Show chat rules and guidelines            ║\n" +
                "║ delete      - Delete your account                       ║\n" +
                "║ exit        - Exit the chat                             ║\n" +
                "╚═════════════════════════════════════════════════════════╝\n" + COLOR_RESET;
            sendToClient(client_socket, help_msg);
            
        } else if (message == "streak") {
            string streak_msg = string(COLOR_CYAN) + "🔥 Your current streak: " + to_string(user_streaks[client_username]) + " days" + COLOR_RESET;
            sendToClient(client_socket, streak_msg);
            
        } else {
            cout << COLOR_YELLOW << "[UNKNOWN] " << client_username << " sent: " << message << COLOR_RESET << endl;
        }
    }
    
    close(client_socket);
}

int main() {
    printWelcomeBanner();
    srand(static_cast<unsigned int>(time(0)));
    
    loadUserData();
    
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        cout << COLOR_RED << "[ERROR] Socket creation failed!" << COLOR_RESET << endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        cout << COLOR_RED << "[ERROR] Bind failed!" << COLOR_RESET << endl;
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, 10) < 0) {
        cout << COLOR_RED << "[ERROR] Listen failed!" << COLOR_RESET << endl;
        close(server_socket);
        return 1;
    }

    cout << COLOR_GREEN << "[SUCCESS] Server listening on port 8080..." << COLOR_RESET << endl;
    printServerStatus(0);

    thread admin_thread(handleAdminCommands);
    admin_thread.detach();

    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket < 0) {
            if (server_running) {
                cout << COLOR_RED << "[ERROR] Accept failed!" << COLOR_RESET << endl;
            }
            continue;
        }
        
        thread client_thread(handleClient, client_socket);
        client_thread.detach();
    }
    
    cout << COLOR_RED << "[SHUTDOWN] Server shutting down..." << COLOR_RESET << endl;
    close(server_socket);
    return 0;
}