//https://www.linkedin.com/pulse/tftp-client-implementation-c-sumit-jha

#include <iostream>
#include <pcap.h>
#include <string>
#include <sys/time.h>
#include <math.h>
#include <arpa/inet.h>
#include <iomanip>
#include <cstring>
#include <map>
#include <ctime>
#include <fstream>
#include <err.h>
#include <stdarg.h>
#include <unistd.h>

#define READ_WRITE_FLAG 0x01
#define DIRECTORY_FLAG  0x02
#define TIMEOUT_FLAG    0x04
#define SIZE_FLAG       0x08
#define MULTICAST_FLAG  0x10
#define MODE_FLAG       0x20
#define ADDRESS_FLAG    0x40
#define ERROR_FLAG      0x80

#define OP_RQ           1
#define OP_WQ           2
#define OP_DATA         3
#define OP_ACK          4
#define OP_ERROR        5

#define ERROR_CODE_UNKNOWN_TID 5

#define buf(X) *(short *)(buffer+X)

std::map<char, std::pair<uint8_t, std::string>> flag_map = {
    { 'R' , {READ_WRITE_FLAG , "0" }},
    { 'W' , {READ_WRITE_FLAG , "0" }},
    { 'd' , {DIRECTORY_FLAG  , "1" }},
    { 't' , {TIMEOUT_FLAG    , "1" }},
    { 's' , {SIZE_FLAG       , "1" }},
    { 'm' , {MULTICAST_FLAG  , "0" }},
    { 'c' , {MODE_FLAG       , "octet" }},
    { 'a' , {ADDRESS_FLAG    , "127.0.0.1,69" }}
};

struct sock_opt_t{
    int sock;
    int operation;
    const char *file;
    int timeout;
    int size;
    const char* mode;
    in_addr address;
    int port;
    int family;
}sock_opt;

int count_words(std::string str){
    int count = 0;
    for (int i = 0; str[i] != '\0';i++)
    {
        if (str[i] == ' ')
            count++;    
    }
    return count+1;
}

std::string print_time(){
    std::string output = "[";
    struct timeval timestamp;
    gettimeofday(&timestamp, nullptr);
    char buff[26];
    int millisec;
    struct tm* tm_info;

    millisec = lrint(timestamp.tv_usec/1000.0);

    tm_info = localtime(&timestamp.tv_sec);

    strftime(buff, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    output.append(buff);
    output.append(".");
    output.append(std::to_string(millisec));
    output.append("] ");
    //std::cout<<output;

    return output;
}

void print(const char *fmt, ...)
{
    va_list args;
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

int read_transfer(sockaddr_in server){
    int count;
    socklen_t server_len;
    char buffer[600];
    bool success = true;

    std::ofstream sfile(sock_opt.file); 
    print("sss", "Requesting READ from server ", flag_map['a'].second.c_str(), "\n");
    do {
        server_len = sizeof server;
        if((count = recvfrom(sock_opt.sock, buffer, 600, 0, (struct sockaddr *)&server, &server_len)) == -1){
            success = false;
            break;
        }
        if (ntohs(*(short *)buffer) == OP_ERROR) {
            print("s", buffer+4);
            success = false;
            break;
        }
        else {
            print("sdsds", "Received block ", ntohs(*(short *)(buffer+2)), " of size ", count-4, " B\n");
            sfile.write(buffer+4, count-4);
            *(short *)buffer = htons(OP_ACK);
            sendto(sock_opt.sock, buffer, 4, 0, (struct sockaddr *)&server,
                    sizeof server);
        }
    } while (count == 516);
    if(success)
        print("s", "Transfer finished successfully without errors\n");
    else
        print("s", "An error occured during transfer\n");

    return 0;
}

int write_transfer(sockaddr_in server){
    char buffer[600];
    char* p;
    int sock = sock_opt.sock;
    socklen_t server_len;
    uint64_t block = 0;
    uint64_t recv_block;
    int sent, count;
    bool success = true;
    int port = 0;

    print("sss", "Requesting WRITE to server ", flag_map['a'].second.c_str(), "\n");
    server_len = sizeof server;
    std::fstream sfile(sock_opt.file); 

    do{
        if((count = recvfrom(sock, buffer, 600, 0, (struct sockaddr *)&server, &server_len)) == -1){
            success = false;
            break;
        }
        // if(port == 0){
        //     //port = server.sin_port;
        //     port = 1;
        // } else {
        //     port = server.sin_port;
        // }
        // if(port != server.sin_port){
        //     print("ss", "Packet with unknown TID received", "\n");
        //     buf(0) = htons(OP_ERROR);
        //     buf(2) = htons(ERROR_CODE_UNKNOWN_TID);
        //     buf(4) = 61;
        //     buf(5) = 0;
        //     sendto(sock, buffer, 6, 0, (struct sockaddr *)&server, sizeof server);
        //     continue;
        // }
        recv_block = ntohs(buf(2));
        if (ntohs(buf(0)) == OP_ERROR) {
            print("ss", buffer+4, "\n");
            success = false;
            break;
        } else if(ntohs(buf(0)) == OP_ACK){
            if(recv_block != block){
                print("sds", "Sending block ", block, " AGAIN\n");
                sent = sendto(sock, buffer, 4+sfile.gcount(), 0, (struct sockaddr *)&server, sizeof server);
            } else{
                if(sfile.gcount() < 512 && block != 0)
                    continue;
                block++;
                buf(0) = htons(OP_DATA);
                buf(2) = htons(block);
                p = buffer + 4;
                sfile.read(p, 512);
                print("sdsds", "Sending block ", block, " of size ", sfile.gcount(), " B\n");
                sent = sendto(sock, buffer, 4+sfile.gcount(), 0, (struct sockaddr *)&server, sizeof server);
            }
        } else {
            print("s", "Nejaky error\n");
        }
        //if(recv_block == 0){
        // print("ss", "Packet with unknown TID received", "\n");
        //     buf(0) = htons(OP_ERROR);
        //     buf(2) = htons(ERROR_CODE_UNKNOWN_TID);
        //     buf(4) = 61;
        //     buf(5) = 0;
        //     sendto(sock, buffer, 6, 0, (struct sockaddr *)&server, sizeof server);
        // }
    } while (sent == 516 || block != recv_block);
    if(success)
        print("s", "Transfer finished successfully without errors\n");
    else
        print("s", "An error occured during transfer\n");
    return 0;
}

int err_cmd(std::string err){
    print("ssss", err.c_str()," : ",  strerror(errno), "\n");
    if(sock_opt.sock >= 0){
        print("s", "Socket closed\n");
        close(sock_opt.sock);
    }
    return -1;
}

int execute_command(){    
    int sock = -1;
    char   buffer[600], *p;
    struct sockaddr_in server;
    char server_message[2000], client_message[2000];

    server.sin_addr = sock_opt.address;
    server.sin_family = sock_opt.family;
    server.sin_port = sock_opt.port;
    
    if ((sock = socket(server.sin_family , SOCK_DGRAM , 0)) == -1){ // vytvoˇren ́ı schr ́anky klient
        return err_cmd("socket() failed");
    }
    print("s", "Socket created successfully\n");
    sock_opt.sock = sock;

    if(sock_opt.timeout >= 0){
        struct timeval timeout;      
        timeout.tv_sec = sock_opt.timeout;
        timeout.tv_usec = 0;
        
        if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                    sizeof timeout) < 0)
            err_cmd("setsockopt failed");

        if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                    sizeof timeout) < 0)
            err_cmd("setsockopt failed");
    }

    //*(short *)buffer = htons(sock_opt.operation);	/* The op-code   */
    buf(0) = htons(sock_opt.operation);
    p = buffer + 2;
    strcpy(p, flag_map['d'].second.c_str());			    /* The file name */
    p += strlen(sock_opt.file)    + 1;	/* Keep the nul  */
    strcpy(p, flag_map['c'].second.c_str());			/* The Mode      */
    p += strlen(sock_opt.mode) + 1;

    server.sin_port = htons(69);
    
    if (sendto(sock, buffer, p-buffer, 0, (struct sockaddr *)&server, sizeof server) != p-buffer)
        return err_cmd("sendto() failed");

    if(sock_opt.operation == OP_RQ){
        read_transfer(server);
    } else {
        write_transfer(server);
    }
    
    close(sock);
    print("s", "Socket closed\n");
    return 0;
}

bool is_number(const std::string s){
    return( strspn( s.c_str(), "0123456789" ) == s.size() );
}

uint8_t set_sock_check_flags_flags(uint8_t flags){
    //READ_WRITE_FLAG & DIRECTORY FLAG
    if(!(flags & READ_WRITE_FLAG) || !(flags & DIRECTORY_FLAG)){
        std::cerr << "FLAGS\n";
        return ERROR_FLAG;
    }

    sock_opt.file = flag_map['d'].second.c_str();
    if(sock_opt.operation == OP_WQ){
        std::fstream test(sock_opt.file); 
        if (!test)
        {
            std::cout<<"INCORRECT FILE PATH\n";
            return ERROR_FLAG;
        }
    }
    

    //ADDRESS_FLAG
    sockaddr_storage storage;
    std::string address;
    std::string port;
    size_t pos;
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
        std::cerr<<"MISSING DELIMITER IN ADDRESS,PORT\n";
        return ERROR_FLAG;
    }
    if(inet_pton(AF_INET, address.c_str(), &sock_opt.address) == 1){
        sock_opt.family = AF_INET;
    } else if (inet_pton(AF_INET6, address.c_str(), &sock_opt.address) == 1){
        sock_opt.family = AF_INET6;
    } else {
        std::cerr<<"INCORRECT ADDRESS\n";
        return ERROR_FLAG;
    }

    //TIMEOUT_FLAG
    if((flags & TIMEOUT_FLAG)){
        if(!is_number(flag_map['t'].second)){
            std::cerr<<"INCORRECT TIMEOUT\n";
            return ERROR_FLAG;
        }
        sock_opt.timeout = atoi(flag_map['t'].second.c_str());
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

    //SIZE_FLAG //TODO:
    
    return flags;
}

void find_and_replace(std::string& subject, const std::string& search,
                          const std::string& replace) {
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}

uint8_t parse_line(std::string command){
    if(command.find("- ") != std::string::npos || command.find("-") == std::string::npos)
        return ERROR_FLAG;
    find_and_replace(command, " ", "");
    find_and_replace(command, "-", " -");
    command.erase(0, 1);
    std::string delimiter = " ";
    size_t pos = 0;
    std::string token;
    uint8_t flags = 0;
    char arg;

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
    return set_sock_check_flags_flags(flags);
}

int whitespace_string(std::string s){
    for(int i=0;i<s.length();i++){
        if(!isspace(s[i]))
            return 0;
    }
    return 1;
}

int process_line(std::string line){
    uint8_t flags = 0;
    if(whitespace_string(line))
        return 0;
    flags |= parse_line(line);
    if(flags & ERROR_FLAG)
        return -1;
    execute_command();
    return 0;
}

void cleanup(){
    flag_map['a'].second = "127.0.0.1,69";
    flag_map['t'].second = "1";
    flag_map['s'].second = "1";
    flag_map['c'].second = "octet";
}

int main(int argc, char **argv){
    std::string line;
    while(1){
        std::cout << "> ";
        getline(std::cin, line);
        if(process_line(line))
            std::cerr << "INCORRECT COMMAND\n";
        cleanup();
    }
    return 0;
}