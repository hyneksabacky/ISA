//  +---------------------------+
//  |      mytftpclient.cpp     |
//  |                           |
//  |   author: Hynek Sabacky   |
//  |       28. 10. 2021        |
//  +---------------------------+                 

#include <iostream>
#include <string>
#include <sys/time.h>
#include <math.h>
#include <arpa/inet.h>
#include <iomanip>
#include <cstring>
#include <map>
#include <fstream>
#include <err.h>
#include <stdarg.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <vector>
#include <iterator>
#include <algorithm>

//  ---- Flags for input arguments ----
#define READ_WRITE_FLAG 0x01        // Read or Write
#define DIRECTORY_FLAG  0x02        // Directory (local or server)
#define TIMEOUT_FLAG    0x04        // Timeout
#define SIZE_FLAG       0x08        // Blocksize of transfer
#define MULTICAST_FLAG  0x10        // Multicast
#define MODE_FLAG       0x20        // Binary or netascii mode
#define ADDRESS_FLAG    0x40        // IPv4 or IPv6 address and port 
#define ERROR_FLAG      0x80        // Incorrect combination of input arguments

// ---- TFTP operation codes in sent packets ----
#define OP_RQ           1           // Read Request
#define OP_WQ           2           // Write Request
#define OP_DATA         3           // Data
#define OP_ACK          4           // Acknowledgement
#define OP_ERROR        5           // Error
#define OP_OACK         6           // Option Acknowledgement

// ---- TFTP error codes in ERROR packets ----
#define ERR_NOT_DEFINED        0    // Not defined, see error message (if any).
#define ERR_FILE_NOT_FOUND     1    // File not found.
#define ERR_ACCESS_VIOLATION   2    // Access violation.
#define ERR_DISK_FULL          3    // Disk full or allocation exceeded.
#define ERR_ILLEGAL_OP         4    // Illegal TFTP operation.
#define ERR_UNKNOWN_TID        5    // Unknown transfer ID.
#define ERR_FILE_EXISTS        6    // File already exists.
#define ERR_NO_SUCH_USER       7    // No such user.
#define ERR_OPTION_NEGOTIATION 8    // Option negotiation error.

#define BUFFERSIZE  ((oack_map["blksize"].second < 512) ? 552 : (oack_map["blksize"].second + 40))  // Determining size of buffer

#define buf(X) *(short *)(buffer+X) // Accessing different bytes of buffer

// +--- Map for input arguments ---+
// |                               |
// |   Used for keeping arguments  |
// |   passed by user and having   |
// |   default arguments. Default  |
// |   values also say if the      |
// |   option has an argument:     |
// |                               |
// |   "0" - no argument           |
// |  <anything else> - argument   |
// +-------------------------------+
std::map<char, std::pair<uint8_t, std::string>> flag_map = {
//   option       flag     default value
    { 'R' , {READ_WRITE_FLAG , "0" }           },   // Read option
    { 'W' , {READ_WRITE_FLAG , "0" }           },   // Write option
    { 'd' , {DIRECTORY_FLAG  , "1" }           },   // Directory option
    { 't' , {TIMEOUT_FLAG    , "1" }           },   // Timeout option
    { 's' , {SIZE_FLAG       , "1" }           },   // Blocksize option
    { 'm' , {MULTICAST_FLAG  , "0" }           },   // Multicast option
    { 'c' , {MODE_FLAG       , "octet" }       },   // Mode option
    { 'a' , {ADDRESS_FLAG    , "127.0.0.1,69" }}    // Address option
};


// +--- Structure for keeping socket and trasnfer arguments ---+
// |                                                           |
// |    Structure to carry all needed arguments across         |
// |    all functions and also keeping important arguments     |
// |    needed for option negotiation. These values are        |
// |    also used during trasfer.                              |
// +-----------------------------------------------------------+
struct sock_opt_t{
    int sock;                   // Socket file descripor
    int operation;              // TFTP operation code
    std::string file; // File name string
    std::vector<unsigned char> file_content;   // Transformed content of file
    int filesize;               // Size of file
    int timeout;                // Timeout
    int size;                   // Blocksize
    const char* mode;           // Mode (netascii/octet)
    in_addr address;            // IPv4 address
    in6_addr address6;          // IPv6 address
    int port;                   // Port
    int family;                 // IPv4 or IPv6 family
}sock_opt;

// +---- Map for option negotiation ----+
// |                                    |
// | Map used during option negotiation |
// | keeping references to sock_opt     |
// | values to modify them during       |
// | transfer.                          |
// +------------------------------------+
std::map<std::string, std::pair<int*, int>> oack_map = {
//  option name        reference     will be accepted/value
    { "tsize"   , {&(sock_opt.filesize),   1}     },    // Transfersize option
    { "blksize" , {&(sock_opt.size),       0}     },    // Blocksize option
    { "timeout" , {&(sock_opt.timeout),    0}     }     // Timeout option
};

/* Function for returning current time in specifed format
 *
 * @returns current time and date in string inside [] parentheses
 */
std::string print_time(){
    std::string output = "[";           // Output that this function returns
    struct timeval timestamp;           // Structure in which timestamp is loaded to
    gettimeofday(&timestamp, nullptr);
    char buff[26];                      // Buffer for strftime function
    int millisec;                       // Milliseconds of timestamp
    struct tm* tm_info;                 // Timestamp structure

    millisec = lrint(timestamp.tv_usec/1000.0);

    tm_info = localtime(&timestamp.tv_sec);

    strftime(buff, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    output.append(buff);
    output.append(".");
    output.append(std::to_string(millisec));
    output.append("] ");

    return output;
}

/* Function to print to stdout in a specified format
 *  @param fmt format string
 *  @param ... strings and integers to print
 */  
void print(const char *fmt, ...)
{
    va_list args;               // Variable number of input args
    va_start(args, fmt);

    std::cout << print_time();

    while (*fmt != '\0') {
        if (*fmt == 'd') {
            int i = va_arg(args, int);
            std::cout << i;
        } else if (*fmt == 's') {
            char * s = va_arg(args, char*);
            std::cout << s;
        }
        ++fmt;
    }

    va_end(args);
}

/*  Function for transforming file. 
 *  Transform a file to netascii or keeps it binary
 *  and reads it into sock_opt.file_content for
 *  later use.
 * 
 *  @returns 0 for success
 *          \ -1 when failed to open file
 */ 
int transform_file(){
    std::ifstream file;                         // File to read from
    if(!strcmp(sock_opt.mode, "netascii")){
        char c;                                 // char to read bytes into
        file.open(sock_opt.file);
        sock_opt.file_content.clear();
        
        if(!file){
            return -1;
        }
        while((c = file.get()) != EOF){
            if(c ==  '\r'){
                sock_opt.file_content.push_back(c);
                if((c = file.get()) == EOF){
                    sock_opt.file_content.push_back('\0');
                    break;
                } else if (c != '\0' && c != '\n'){
                    sock_opt.file_content.push_back('\0');
                    file.unget();
                } else {
                    sock_opt.file_content.push_back(c);
                }         
            } else if (c == '\n'){
                sock_opt.file_content.push_back('\r');
                sock_opt.file_content.push_back(c);
            } else {
                sock_opt.file_content.push_back(c);
            }
        }
        sock_opt.filesize = sock_opt.file_content.size();
    } else {
        struct stat results;                                                // Structure for file statistics
    
        if (stat(sock_opt.file.c_str(), &results) == 0)
            sock_opt.filesize = results.st_size;

        file.open(sock_opt.file, std::ios::binary);
        file.unsetf(std::ios::skipws);
        if(file.is_open()){
            std::stringstream strStream(std::ios::binary | std::ios::in);
            sock_opt.file_content.reserve(results.st_size);

            sock_opt.file_content.insert(sock_opt.file_content.begin(),
               std::istream_iterator<unsigned char>(file),
               std::istream_iterator<unsigned char>());
        }else{
            return -1;
        }
    }
    std::reverse(sock_opt.file_content.begin(),sock_opt.file_content.end());
    oack_map["tsize"].second = sock_opt.filesize;

    file.close();
    return 0;
}

/*  Function to read specified amount of characters
 *  from sock_opt.file_content (user specified file).
 *  If theres not enough characters to read, it read
 *  as many as it can.
 *
 *  @param buffer buffer in which to put read characters
 *  @param count max amount of characters to read
 * 
 *  @returns number of characters read
 */
int read_file(char* buffer, int count){
    int i = 0;                                          // Counter
    for(i; i<count;i++){
        if(sock_opt.file_content.empty()){
            break;
        } else {
            *buffer = sock_opt.file_content.back();
            buffer++;
            sock_opt.file_content.pop_back();
        }
    }
    return i;

}

/*  Function to print transfer error to stdout.
 *
 *  @param err error string to print
 * 
 *  @returns -1
 */
int err_cmd(std::string err){
    print("ssss", err.c_str()," : ",  strerror(errno), "\n");
    if(sock_opt.sock >= 0){
        //print("s", "Socket closed\n");
        close(sock_opt.sock);
    }
    return -1;
}

/*  Function to get the minimum MTU of all
 *  interfaces using ioctl.
 *
 *  @returns minimum MTU or 512 if ioctl failed
 */
int get_mtu_size()
{
    int sock = sock_opt.sock;                   // Socket file descriptor
    struct ifreq ifr;                           // struct ifreq
    struct ifaddrs* ifaddr, *tmp;               // All interfaces list
    int ret = 0;                                // Retrun value
    int min_mtu = INT32_MAX;                    // Minimum MTU of all interfaces
    getifaddrs(&ifaddr);
    tmp = ifaddr;
    while(ifaddr != nullptr){
        struct sockaddr_in *sa = (struct sockaddr_in *) ifaddr->ifa_addr;
        char *addr = inet_ntoa(sa->sin_addr);
        strcpy(ifr.ifr_name , ifaddr->ifa_name); 
        ret = ioctl(sock, SIOCGIFMTU, &ifr);
        min_mtu = (ifr.ifr_mtu-72) < min_mtu ? (ifr.ifr_mtu-72) : min_mtu; // 36 = size of (ethernet + ipv6 + udp) headers
        ifaddr = ifaddr->ifa_next;
    }
    freeifaddrs(tmp);
    if(!ret) {
        return min_mtu; 
    } else return 512;
}

/*  Function to parse option name or value
 *
 *  @param buffer buffer from which to parse
 *  @param count remaining buffer size
 * 
 *  @return the parsed value
 */
std::string get_option(char *buffer, int *count){
    std::string val = "";           // string to return
    while(*buffer != '\0'){
        if(*count > 0){
            val.push_back(*buffer);
        } else
            return "";
        *count = *count -1;
        buffer++;
    }
    buffer++;
    *count = *count -1;
    return val;
}


/*  Function to get option value.
 *
 *  @param buffer buffer from which to parse
 *  @param count remaining buffer size 
 *  
 *  @return the value as integer
 */
int get_value(char *buffer, int *count){
    std::string str;    // string to return if its not empty
    return ((str = get_option(buffer, count)) != "") ? atoi(str.c_str()) : -1;
}

/*  Sets socket timeout
 *
 *  @param socket socket file descriptor
 *  @param timeout_sec timeout in seconds
 *  @param timeout_usec timeout in microseconds
 */ 
void set_sock_timeout(int socket, int timeout_sec, int timeout_usec){ //FIXME:
    struct timeval timeout;             // Time
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = timeout_usec;
    
    // configure socket for timeout
    if (setsockopt (sock_opt.sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                sizeof timeout) < 0)
        err_cmd("setsockopt failed");

    if (setsockopt (sock_opt.sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                sizeof timeout) < 0)
    err_cmd("setsockopt failed");
}

/*  Function for parsing all options and
 *  assigning them to correct variables
 *  using oack_map.
 * 
 *  @param buffer buffer from which to parse
 *  @param count remaining buffer size
 * 
 *  @return -1 when success
 *          \ 8 - option negotiation error
 */
int set_option_ack(char *buffer, int count){
    std::string opt;                        // Option name
    int val;                                // Option value
    int ret = -1;                           // Return value
    int rem_count = count;                  // Number of remaining bytes
    while(count >0){
        opt = get_option(buffer, &count);
        buffer += rem_count - count;
        rem_count = count;
        if((val = get_value(buffer, &count)) == -1)
            ret = ERR_OPTION_NEGOTIATION;
        buffer += rem_count - count;
        rem_count = count;
        if(oack_map.count(opt) && oack_map[opt].second >= 0){
            if(opt == "tsize"){
                if(sock_opt.operation == OP_WQ && val != oack_map[opt].second){
                    ret = ERR_OPTION_NEGOTIATION;
                } else {
                    *(oack_map[opt].first) = val;
                }
            } else if(opt == "timeout"){
                if(val != oack_map[opt].second){
                    ret = ERR_OPTION_NEGOTIATION;
                } else {
                    *(oack_map[opt].first) = val;
                }
            } else {
                if(val <= oack_map[opt].second && val > 0)
                    *(oack_map[opt].first) = val;
                else    
                    ret = ERR_OPTION_NEGOTIATION;
            }
        } else{
            ret = ERR_OPTION_NEGOTIATION;
        }
    }

    if(sock_opt.size == 0){
        return ERR_OPTION_NEGOTIATION;
    }

    if(sock_opt.timeout >= 0){
        set_sock_timeout(sock_opt.sock, sock_opt.timeout, 0);
    }

    return ret;
}


/*  Function that builds a TFTP packet and sends it
 *
 *  @param server destination
 *  @param buffer buffer in which to store packet data
 *  @param op_code operation code of the packet
 *  @param spec_code additional code for specific operation
 * 
 *  @return count of sent bytes
 */
int prepare_and_send_packet(sockaddr_in server, char* buffer, int op_code, int spec_code){
    int read_count;                             // Number of bytes read from file
    int size = 0;                               // Size of packet to send 
    char* p = buffer+4;                         // Buffer with packet data
    buf(0) = htons(op_code);
    buf(2) = htons(spec_code);
    if(op_code = OP_DATA){
        read_count = read_file(p, sock_opt.size);
        size = read_count+4;      
    } else if (op_code == OP_ERROR){
        buf(4) = htons(0);
        size = 5;
    } else if (op_code == OP_ACK){
        size = 4;
    }

    return sendto(sock_opt.sock, buffer, size, 0, (struct sockaddr *)&server,
                    sizeof server); 
    
}


/*  Function that prints the result of transfer
 *
 *  @param result code which translates to result: -1 success, -2 serverside error,  0-8 client side error
 *  @param buffer Packet data buffer
 *  @param server Server address
 */
void print_result(int type, int result, char * buffer, sockaddr_in server){
    if(result == -1)
        print("s", "Transfer finished successfully without errors\n");
    else if(result == -2){
        print("s", "An error occured during transfer\n");
        if(type == 0){
            remove(sock_opt.file.c_str());
        }
    } else{
        print("s", "An error occured during transfer\n");
        prepare_and_send_packet(server, buffer, OP_ERROR, result);
        remove(sock_opt.file.c_str());
    }
}

/*  Function that handles the whole read request transfer.
 *
 *  @param server server address structure to use for sendto and recvfrom
 */
void read_transfer(sockaddr_in server){
    int count;                          // Number of packets read
    socklen_t server_len;               // Server address
    char buffer[BUFFERSIZE];            // Buffer for packet data
    int success = -1;                   // Return state
    int block = 0;                      // Block number
    int recv_block = 0;                 // Last received block number
    int port = 0;                       // server TID
    int fin = 0;                        // Transfer should end: 0 - not end, 1 - wait last ACK received, 2 - end

    std::ofstream sfile(sock_opt.file); // File to write to
    if(sock_opt.timeout < 0) 
        set_sock_timeout(sock_opt.timeout, 5 , 0);
    do {
        server_len = sizeof server;
        if(fin == 1){
            set_sock_timeout(sock_opt.timeout, 0 , 100);
        }
        if((count = recvfrom(sock_opt.sock, buffer, BUFFERSIZE , 0, (struct sockaddr *)&server, &server_len)) == -1){
            if(sock_opt.timeout < 0 && fin <1){
                print("s", "Destination unreachable\n");
                success = -2;
                break;
            } 
            buf(0) = htons(OP_DATA);
            if(fin == 1){
                break;
            }
        } else {
            if(port == 0){
                port = ntohs(server.sin_port);
                if(sock_opt.timeout < 0) 
                    set_sock_timeout(sock_opt.timeout, 0, 0);
            } if(port != ntohs(server.sin_port)) {
                server.sin_port = htons(port);
                prepare_and_send_packet(server, buffer, OP_ERROR, ERR_UNKNOWN_TID);
                continue;
            }
        }
        if (ntohs(buf(0)) == OP_ERROR) {
            print("ss", buffer+4, "\n");
            success = -2;
            break;
            continue;
        }
        else if (ntohs(buf(0)) == OP_DATA){
            if(sock_opt.filesize)
                print("sdsdsdsds", "Received block ", ntohs(buf(2)), ": ", (ntohs(buf(2))-1)*sock_opt.size, " ... ", (ntohs(buf(2))-1)*sock_opt.size+count-4, " of ", sock_opt.filesize, " B \n");
            else
                print("sdsdsds", "Received block ", ntohs(buf(2)), ": ", (ntohs(buf(2))-1)*sock_opt.size, " ... ", (ntohs(buf(2))-1)*sock_opt.size+count-4," B\n");
            sfile.write(buffer+4, count-4);
            if(sfile.bad()){
                success = ERR_DISK_FULL;
                break;
            }
            if(recv_block+1 != ntohs(buf(2)) && recv_block != ntohs(buf(2))){
                    success = ERR_ILLEGAL_OP;
                    break;
                }
            recv_block = ntohs(buf(2));
            prepare_and_send_packet(server, buffer, OP_ACK, recv_block);
            if(count < sock_opt.size +4)
                fin = 1;
        } else if(ntohs(buf(0)) == OP_OACK) {
            if(recv_block != 0){
                success = ERR_ILLEGAL_OP;
                break;
            }
            if((success = set_option_ack(buffer+2, count-2)) != -1){
                break;
            }   
            prepare_and_send_packet(server, buffer, OP_ACK, recv_block)  ;   
        }
    } while (count == sock_opt.size +4 || sfile.tellp() == 0 || fin == 1);
    print_result(0, success, buffer, server);

    sfile.close();
}

/*  Function that handles the whole write request transfer.
 *
 *  @param[in] server server address structure to use for sendto and recvfrom
 */
void write_transfer(sockaddr_in server){
    char buffer[BUFFERSIZE];        // Buffer for packet data
    char* p;                        // Help buffer for packet data
    int sock = sock_opt.sock;       // Socket file descriptor
    socklen_t server_len;           // Server length
    uint64_t block = 0;             // Block number
    uint64_t recv_block;            // Last received block number
    int sent;                       // Sent byte count
    int count;                      // Received byte count
    int success = -1;               // Result state
    int port = 0;                   // Server TID
    int read_count = 0;             // Number of read bytes from file
    server_len = sizeof server; 

    if(sock_opt.timeout < 0) 
        set_sock_timeout(sock_opt.timeout, 5 , 0);
    do{
        if((count = recvfrom(sock, buffer, 600, 0, (struct sockaddr *)&server, &server_len)) < 0){
            if(sock_opt.timeout < 0){
                print("s", "Destination unreachable\n");
                success = -2;
                break;
            }
            buf(0) = htons(OP_ACK);
            buf(2) = htons(recv_block);
        } else {
            if(port == 0){
                if(sock_opt.timeout < 0) 
                    set_sock_timeout(sock_opt.timeout, 0 , 0);
                port = ntohs(server.sin_port);
            } else if(port != ntohs(server.sin_port)) {
                prepare_and_send_packet(server, buffer, OP_ERROR, ERR_UNKNOWN_TID);
                continue;
            }
        }
        if (ntohs(buf(0)) == OP_ERROR) {
            print("ss", buffer+4, "\n");
            success = -2;
            break;
        } else if(ntohs(buf(0)) == OP_ACK){
            recv_block = ntohs(buf(2));
            if(recv_block != block){
                if(recv_block+1 != block){
                    success = ERR_ILLEGAL_OP;
                    break;
                }
                print("sds", "Sending block ", block, " AGAIN\n");
                sent = prepare_and_send_packet(server, buffer, OP_DATA, block);
            } else{
                if(read_count < sock_opt.size && block != 0)
                    continue;
                block++;
                sent = prepare_and_send_packet(server, buffer, OP_DATA, block);
                read_count = sent-4;
                print("sdsdsdsds", "Sending block ", block, ":  ", (block-1)*sock_opt.size, "...",(block-1)*sock_opt.size+read_count, " B of ", sock_opt.filesize, " B\n");
            }
        } else if(ntohs(buf(0)) == OP_OACK) {
            if(block>0){
                success = ERR_ILLEGAL_OP;
                break;
            }
            if((success = set_option_ack(buffer+2, count-2)) != -1){
                break;
            }
            block++;   
            sent = prepare_and_send_packet(server, buffer, OP_DATA, block);
            read_count = sent - 4;
            print("sdsdsdsds", "Sending block ", block, ":  ", (block-1)*sock_opt.size, "...",(block-1)*sock_opt.size+read_count, " B of ", sock_opt.filesize, " B\n");
            
        }
    } while (sent == sock_opt.size+4 || block != recv_block);
    print_result(1, success, buffer, server);
}

/*  Function that sets up socket for transfer, creates it and sends first message
 *
 *  @return 0 for success \ -1 for failure
 * 
 */
int execute_command(){    
    int sock = -1;                  // Socket file descriptor
    char   buffer[600], *p;         // Buffer for packet data 
    struct sockaddr_in *serverout;  // Final server address
    struct sockaddr_in server;      // IPv4 server address
    struct sockaddr_in6 server6;    // IPv6 server address

    if(sock_opt.family == AF_INET){
        server.sin_family = sock_opt.family;
        server.sin_port = sock_opt.port;
        server.sin_addr = sock_opt.address;
        serverout = (sockaddr_in *)&server;
    } else {
        server6.sin6_addr = sock_opt.address6;
        server6.sin6_family = sock_opt.family;
        server6.sin6_port = sock_opt.port;
        serverout = (sockaddr_in *)&server6; 
    }
        
    if ((sock = socket(sock_opt.family , SOCK_DGRAM , 0)) == -1){
        return -1;
    }

    sock_opt.sock = sock;

    
    buf(0) = htons(sock_opt.operation);
    p = buffer + 2;
    strcpy(p, sock_opt.file.c_str());
    p += strlen(sock_opt.file.c_str())    + 1;
    strcpy(p, flag_map['c'].second.c_str());
    p += strlen(sock_opt.mode) + 1;
    strcpy(p, "tsize");
    p += strlen("tsize")+1;
    strcpy(p, std::to_string(sock_opt.filesize).c_str());
    p += snprintf(0,0,"%+d",sock_opt.filesize);
    if(oack_map["blksize"].second > 0 ){
        int min_mtu = get_mtu_size();
        oack_map["blksize"].second = min_mtu < oack_map["blksize"].second ? min_mtu : oack_map["blksize"].second;
        strcpy(p, "blksize");
        p += strlen("blksize")+1;
        strcpy(p, std::to_string(oack_map["blksize"].second).c_str());
        p += snprintf(0,0,"%+d",oack_map["blksize"].second);
    }
    if(oack_map["timeout"].second>0){
        strcpy(p, "timeout");
        p += strlen("timeout")+1;
        strcpy(p, std::to_string(oack_map["timeout"].second).c_str());
        p += snprintf(0,0,"%+d",oack_map["timeout"].second);
    }

    if(sock_opt.operation == OP_RQ){
        print("sss", "Requesting READ from server ", flag_map['a'].second.c_str(), "\n"); //FIXME:
    } else {
        print("sss", "Requesting WRITE to server ", flag_map['a'].second.c_str(), "\n");
    }
    
    if (sendto(sock, buffer, p-buffer, 0, (struct sockaddr *)serverout, sizeof server) != p-buffer)
        return err_cmd("sendto() failed");

    if(sock_opt.operation == OP_RQ){
        read_transfer(*serverout);
    } else {      
        write_transfer(*serverout);
    }
    
    close(sock);
    return 0;
}

/*  Function to test if a string is a number
 *
 *  @param s string to be tested
 *
 *  @returns true if the string is a number
 */
bool is_number(const std::string s){
    return( strspn( s.c_str(), "0123456789" ) == s.size() );
}

/*  Function that checks input arguments and sets up sock_opt structure and oack_map.
 *
 *  @param flags input argument flags
 * 
 *  @returns the flags
 */
uint8_t set_sock_check_flags(uint8_t flags){
    //READ_WRITE_FLAG & DIRECTORY FLAG
    if(!(flags & READ_WRITE_FLAG) || !(flags & DIRECTORY_FLAG)){
        std::cerr << "FLAGS\n";
        return ERROR_FLAG;
    }

    //ADDRESS_FLAG
    std::string address;    // IP address
    std::string port;       // Destination port
    size_t pos;             // Position of searched character
    if ((pos = flag_map['a'].second.find(",")) != std::string::npos){
        flag_map['a'].second.replace(pos, 1, ":");
        address = flag_map['a'].second.substr(0, pos);
        port = flag_map['a'].second.substr(pos, flag_map['a'].second.length());
        if(port.length()<2 || !is_number(port.substr(1, port.length()))){
            std::cerr<<"INCORRECT PORT\n";
            return ERROR_FLAG;
        }
        sock_opt.port = htons(atoi(port.substr(1, port.length()).c_str()));
    } else {
        address = flag_map['a'].second;
        flag_map['a'].second.append(":69");
        sock_opt.port = htons(69);
    }
    if(inet_pton(AF_INET, address.c_str(), &sock_opt.address) == 1){
        sock_opt.family = AF_INET;
    } else if (inet_pton(AF_INET6, address.c_str(), &sock_opt.address6) == 1){
        sock_opt.family = AF_INET6;
    } else {
        std::cerr<<"INCORRECT ADDRESS\n";
        return ERROR_FLAG;
    }

    //TIMEOUT_FLAG
    if((flags & TIMEOUT_FLAG)){
        if(!is_number(flag_map['t'].second) || atoi(flag_map['t'].second.c_str()) < 1 || atoi(flag_map['t'].second.c_str()) > 255){
            std::cerr<<"INCORRECT TIMEOUT\n";
            return ERROR_FLAG;
        }
        sock_opt.timeout = -1;
        oack_map["timeout"].second = atoi(flag_map['t'].second.c_str());
    } else {
        sock_opt.timeout = -1;
    }

    //MODE_FLAG
    if(flag_map['c'].second == "ascii")
        flag_map['c'].second = "netascii";
    else if (flag_map['c'].second == "binary")
        flag_map['c'].second = "octet";
    if(flag_map['c'].second != "netascii" && flag_map['c'].second != "octet")
    {
        std::cerr << "INCORRECT MODE\n";
        return ERROR_FLAG;
    } else {
        sock_opt.mode = flag_map['c'].second.c_str();
    }

    //FILE_FLAG
    sock_opt.file = flag_map['d'].second;
    if(sock_opt.operation == OP_WQ){
        if(transform_file())
            return ERROR_FLAG;
        size_t pos = flag_map['d'].second.find_last_of('/');
        if(pos == std::string::npos)
            pos = -1;
        sock_opt.file = flag_map['d'].second.substr(pos+1);
    } else {
        struct stat buffer;   
        if (stat(flag_map['d'].second.c_str(), &buffer) == 0){
            flag_map['d'].second = "";
            std::cerr << "FILE EXISTS\n";
            return ERROR_FLAG;
        }
        sock_opt.filesize = 0;
    }

    //SIZE_FLAG
    if((flags & SIZE_FLAG)){
        if(!is_number(flag_map['s'].second) || atoi(flag_map['s'].second.c_str()) < 1){
            std::cerr<<"INCORRECT SIZE\n";
            return ERROR_FLAG;
        }
        sock_opt.size = 512;
        oack_map["blksize"].second = atoi(flag_map['s'].second.c_str());
    } else {
        sock_opt.size = 512;
        oack_map["blksize"].second = 0;
    }
    
    return flags;
}

/*  Function that finds a substring in string and replaces it with another string.
 *
 *  @param subject a string in which to search
 *  @param search a string to search for
 *  @param replace a string to replace the found substring
 */
void find_and_replace(std::string& subject, const std::string& search,
                          const std::string& replace) {
    size_t pos = 0;     // Position of searched character/string
    while ((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}

/*  Function that parses input command
 *
 *  @param command command string
 * 
 *  @returns input argument flags
 */
uint8_t parse_line(std::string command){
    if(command.find("- ") != std::string::npos || command.find("-") == std::string::npos)
        return ERROR_FLAG;
    find_and_replace(command, " ", "");
    find_and_replace(command, "-", " -");
    command.erase(0, 1);
    std::string delimiter = " ";        // " " - Space delimiter
    size_t pos = 0;                     // Position in string
    std::string token;                  // Parsed token from input
    uint8_t flags = 0;                  // Argument flags
    char arg;                           // Argument letter

    if(command.find_first_not_of(' ') != std::string::npos)
    {
        do{
            pos = command.find(delimiter);
            token = command.substr(0, pos);
            command.erase(0, pos + delimiter.length());
            if(token[0] != '-' || token.length() < 2){
                std::cerr << "TOKEN LENGTH/ -\n";
                return ERROR_FLAG;
            }
            arg = token[1];
            token.erase(0, 2);
            if(flag_map.count(arg) == 0 || flags&flag_map[arg].first){
                std::cerr << "NOT FOUND OR REUSED ARG\n";
                return ERROR_FLAG;
            }
            flags |= flag_map[arg].first;
            if(arg == 'W')
                sock_opt.operation = OP_WQ;
            else if(arg == 'R')
                sock_opt.operation = OP_RQ;
            if(flag_map[arg].second != "0"){
                if(token.length()<1){
                    std::cerr << "\n\"-" << arg << "\" needs an argument\n";
                    return ERROR_FLAG;
                }
                flag_map[arg].second = token;
            }
        } while (pos != std::string::npos);
    } else {
        return 0;
    }
    return set_sock_check_flags(flags);
}

/*  Function that checks if a string is whitespaces only.
 *
 *  @param s string to check
 * 
 *  @returns true if a string is whitespaces only
 */
bool whitespace_string(std::string s){
    for(int i=0;i<s.length();i++){
        if(!isspace(s[i]))
            return false;
    }
    return true;
}

/* Function that calls setting up functions and calls a function to execute the command
 *
 *  @param line string of a line to parse (command)
 * 
 *  @return true if the command was correct
 */
int process_line(std::string line){
    uint8_t flags = 0;  // Argument flags
    if(whitespace_string(line))
        return 0;
    flags |= parse_line(line);
    if(flags & ERROR_FLAG)
        return -1;
    execute_command();
    return 0;
}

// Function that cleanes up flag_map between commands
void cleanup(){
    flag_map['a'].second = "127.0.0.1,69";
    flag_map['t'].second = "1";
    flag_map['s'].second = "1";
    flag_map['c'].second = "octet";
}

int main(){
    std::string line;   // Line read from stdin
    std::cout << "> ";
    while(getline(std::cin, line)){     
        if(process_line(line))
            std::cerr << "INCORRECT COMMAND\n";
        cleanup();
        std::cout << "> ";
    }
    std::cout << "\n";
    return 0;
}