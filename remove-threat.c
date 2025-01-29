#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #define LOG_FILE "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
    #include <windows.h>
    #define popen _popen
    #define pclose _pclose
#else
    #define LOG_FILE "/var/ossec/logs/active-responses.log"
    #include <unistd.h>
#endif

#define INITIAL_BUFFER_SIZE 4096
#define MAX_BUFFER_SIZE 1048576  // 1MB maximum buffer size
#define OS_SUCCESS 0
#define OS_INVALID -1

#define ADD_COMMAND 0
#define DELETE_COMMAND 1
#define CONTINUE_COMMAND 2
#define ABORT_COMMAND 3

// Buffer structure
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} Buffer;

// Function declarations
void write_debug_file(const char* ar_name, const char* msg);
char* get_json_value(const char* json, const char* key);
int setup_and_check_message(const char* ar_name, char** input_str);
int send_keys_and_check_message(const char* ar_name, const char* rule_id);
Buffer* buffer_create(size_t initial_capacity);
void buffer_destroy(Buffer* buffer);
int buffer_append(Buffer* buffer, const char* str, size_t len);
char* read_json_input(void);

// Write debug information to log file
void write_debug_file(const char* ar_name, const char* msg) {
    FILE* log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now;
        struct tm* timeinfo;
        char timestamp[26];
        
        time(&now);
        timeinfo = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y/%m/%d %H:%M:%S", timeinfo);
        
        const char* ar_part = strstr(ar_name, "active-response");
        if (!ar_part) ar_part = ar_name;
        
        fprintf(log_file, "%s %s: %s\n", timestamp, ar_part, msg);
        fclose(log_file);
    }
}

// Execute system command and log output
void execute_command(const char* ar_name, const char* command) {
    char output[1024];
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        write_debug_file(ar_name, "Failed to execute command");
        return;
    }

    while (fgets(output, sizeof(output), fp) != NULL) {
        write_debug_file(ar_name, output);
    }
    pclose(fp);
}

// Initialize buffer
Buffer* buffer_create(size_t initial_capacity) {
    Buffer* buffer = (Buffer*)malloc(sizeof(Buffer));
    if (!buffer) return NULL;
    
    buffer->data = (char*)malloc(initial_capacity);
    if (!buffer->data) {
        free(buffer);
        return NULL;
    }
    
    buffer->size = 0;
    buffer->capacity = initial_capacity;
    buffer->data[0] = '\0';
    return buffer;
}

// Free buffer
void buffer_destroy(Buffer* buffer) {
    if (buffer) {
        free(buffer->data);
        free(buffer);
    }
}

// Append to buffer
int buffer_append(Buffer* buffer, const char* str, size_t len) {
    if (buffer->size + len + 1 > buffer->capacity) {
        size_t new_capacity = buffer->capacity * 2;
        if (new_capacity > MAX_BUFFER_SIZE) return 0;
        
        char* new_data = (char*)realloc(buffer->data, new_capacity);
        if (!new_data) return 0;
        
        buffer->data = new_data;
        buffer->capacity = new_capacity;
    }
    
    memcpy(buffer->data + buffer->size, str, len);
    buffer->size += len;
    buffer->data[buffer->size] = '\0';
    return 1;
}

// Read complete JSON input
char* read_json_input() {
    Buffer* buffer = buffer_create(INITIAL_BUFFER_SIZE);
    if (!buffer) return NULL;
    
    char temp[1024];
    int brackets = 0;
    int in_string = 0;
    int escape = 0;
    
    while (fgets(temp, sizeof(temp), stdin)) {
        size_t len = strlen(temp);
        
        for (size_t i = 0; i < len; i++) {
            if (escape) {
                escape = 0;
                continue;
            }
            
            if (temp[i] == '\\') {
                escape = 1;
                continue;
            }
            
            if (temp[i] == '"' && !escape) {
                in_string = !in_string;
                continue;
            }
            
            if (!in_string) {
                if (temp[i] == '{') brackets++;
                else if (temp[i] == '}') brackets--;
            }
        }
        
        if (!buffer_append(buffer, temp, len)) {
            buffer_destroy(buffer);
            return NULL;
        }
        
        if (brackets == 0 && buffer->size > 0) {
            char* result = strdup(buffer->data);
            buffer_destroy(buffer);
            return result;
        }
    }
    
    buffer_destroy(buffer);
    return NULL;
}

// Parse JSON value
char* get_json_value(const char* json, const char* key) {
    static char value[INITIAL_BUFFER_SIZE];
    char* start;
    char* end;
    char search_key[INITIAL_BUFFER_SIZE];
    
    snprintf(search_key, sizeof(search_key), "\"%s\":\"", key);
    start = strstr(json, search_key);
    
    if (!start) {
        snprintf(search_key, sizeof(search_key), "\"%s\":", key);
        start = strstr(json, search_key);
        if (!start) return NULL;
    }
    
    start += strlen(search_key);
    if (*start == '"') start++;
    
    end = strchr(start, '"');
    if (!end) {
        end = strchr(start, ',');
        if (!end) {
            end = strchr(start, '}');
            if (!end) return NULL;
        }
    }
    
    strncpy(value, start, end - start);
    value[end - start] = '\0';
    return value;
}

// Setup and check initial message
int setup_and_check_message(const char* ar_name, char** input_str) {
    *input_str = read_json_input();
    if (!*input_str) {
        write_debug_file(ar_name, "Error reading input");
        return OS_INVALID;
    }
    
    write_debug_file(ar_name, *input_str);
    
    char* command = get_json_value(*input_str, "command");
    if (!command) {
        write_debug_file(ar_name, "Invalid JSON input");
        return OS_INVALID;
    }
    
    if (strcmp(command, "add") == 0) {
        return ADD_COMMAND;
    } else if (strcmp(command, "delete") == 0) {
        return DELETE_COMMAND;
    }
    
    write_debug_file(ar_name, "Not valid command");
    return OS_INVALID;
}

// Send keys and check response
int send_keys_and_check_message(const char* ar_name, const char* rule_id) {
    char keys_msg[INITIAL_BUFFER_SIZE];
    char* response;
    
    snprintf(keys_msg, sizeof(keys_msg),
             "{\"version\":1,\"origin\":{\"name\":\"%s\",\"module\":\"active-response\"},"
             "\"command\":\"check_keys\",\"parameters\":{\"keys\":[\"%s\"]}}", 
             ar_name, rule_id);
    
    write_debug_file(ar_name, keys_msg);
    printf("%s\n", keys_msg);
    fflush(stdout);
    
    response = read_json_input();
    if (!response) {
        write_debug_file(ar_name, "Error reading response");
        return OS_INVALID;
    }
    
    write_debug_file(ar_name, response);
    
    char* action = get_json_value(response, "command");
    free(response);
    
    if (!action) {
        write_debug_file(ar_name, "Invalid response format");
        return OS_INVALID;
    }
    
    if (strcmp(action, "continue") == 0) {
        return CONTINUE_COMMAND;
    } else if (strcmp(action, "abort") == 0) {
        return ABORT_COMMAND;
    }
    
    write_debug_file(ar_name, "Invalid value of 'command'");
    return OS_INVALID;
}

// Manage Windows firewall
void manage_windows_firewall(const char* ar_name) {
    execute_command(ar_name, "netsh advfirewall reset");
    execute_command(ar_name, "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
    execute_command(ar_name, "netsh advfirewall firewall add rule name=\"RDP\" dir=in action=allow protocol=TCP localport=3389");
    write_debug_file(ar_name, "Windows firewall configured: All ports blocked except RDP (3389)");
}

// Manage Linux firewall
void manage_linux_firewall(const char* ar_name) {
    execute_command(ar_name, "iptables -F");
    execute_command(ar_name, "iptables -X");
    execute_command(ar_name, "iptables -P INPUT DROP");
    execute_command(ar_name, "iptables -P FORWARD DROP");
    execute_command(ar_name, "iptables -P OUTPUT ACCEPT");
    execute_command(ar_name, "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");
    execute_command(ar_name, "iptables -A INPUT -i lo -j ACCEPT");
    execute_command(ar_name, "iptables -A INPUT -p tcp --dport 22 -j ACCEPT");
    
    #if defined(__debian__) || defined(__ubuntu__)
        execute_command(ar_name, "iptables-save > /etc/iptables/rules.v4");
    #elif defined(__centos__) || defined(__redhat__)
        execute_command(ar_name, "service iptables save");
    #else
        execute_command(ar_name, "iptables-save > /etc/sysconfig/iptables");
    #endif
    
    write_debug_file(ar_name, "Linux firewall configured: All ports blocked except SSH (22)");
}

int main(int argc, char** argv) {
    char* input_str = NULL;
    char rule_id[INITIAL_BUFFER_SIZE];
    
    if (argc < 1) {
        return OS_INVALID;
    }
    
    write_debug_file(argv[0], "Started");
    
    int command = setup_and_check_message(argv[0], &input_str);
    if (command < 0 || !input_str) {
        free(input_str);
        return OS_INVALID;
    }
    
    if (command == ADD_COMMAND) {
        char* parameters = strstr(input_str, "\"parameters\"");
        if (!parameters) {
            write_debug_file(argv[0], "No parameters found");
            free(input_str);
            return OS_INVALID;
        }
        
        char* alert = strstr(parameters, "\"alert\"");
        if (!alert) {
            write_debug_file(argv[0], "No alert found");
            free(input_str);
            return OS_INVALID;
        }
        
        char* rule = strstr(alert, "\"rule\"");
        if (!rule) {
            write_debug_file(argv[0], "No rule found");
            free(input_str);
            return OS_INVALID;
        }
        
        char* id = get_json_value(rule, "id");
        if (!id) {
            write_debug_file(argv[0], "No rule ID found");
            free(input_str);
            return OS_INVALID;
        }
        
        strncpy(rule_id, id, sizeof(rule_id));
        free(input_str);
        
        int action = send_keys_and_check_message(argv[0], rule_id);
        if (action != CONTINUE_COMMAND) {
            if (action == ABORT_COMMAND) {
                write_debug_file(argv[0], "Aborted");
                return OS_SUCCESS;
            }
            write_debug_file(argv[0], "Invalid command");
            return OS_INVALID;
        }
        
        #ifdef _WIN32
            manage_windows_firewall(argv[0]);
        #else
            manage_linux_firewall(argv[0]);
        #endif
        
    } else if (command == DELETE_COMMAND) {
        free(input_str);
        write_debug_file(argv[0], "Delete command received - no action needed");
    } else {
        free(input_str);
        write_debug_file(argv[0], "Invalid command");
    }
    
    write_debug_file(argv[0], "Ended");
    return OS_SUCCESS;
}
