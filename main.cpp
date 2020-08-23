/*
 * ISA - Project POP3 client
 * Author: Tomáš Blažek
 * Login: xblaze31
 */

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <list>
#include <vector>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


using namespace std;

#define BUFSIZE 1024

/**
 * Object which hold informations about arguments from command line.
 */
class Arguments {
public:
    char *server_name;
    int pflag;
    char* port;
    int aflag;
    char *auth_file;
    int oflag;
    char *out_dir;
    int nflag;
    int dflag;
    int Tflag;
    int Sflag;
    int cflag;
    char *certificate;
    int Cflag;
    char *certaddr;

    Arguments(){
        server_name = NULL;
        pflag = 0;
        port = NULL;
        aflag = 0;
        auth_file = NULL;
        oflag = 0;
        out_dir = NULL;
        nflag = 0;
        dflag = 0;
        Tflag = 0;
        Sflag = 0;
        cflag = 0;
        certificate = NULL;
        Cflag = 0;
        certaddr = NULL;
    }
};


//Global variables
Arguments *args;
SSL *ssl_socket;
bool encryption;

/**
 * Print help.
 */
void printHelp(){
    printf("Pop3 client made by xblaze31\n");
    printf("Usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>\n\n");
    printf("Non-Optional parameters:\n");
    printf("<server>\tIP address or domain name of pop3 server\n");
    printf("-a Authentification file name\n");
    printf("-o Ouput folder name\n\n");
    printf("Optional parameters:\n");
    printf("-h Open this help (When -h is used nothig else isnt done)\n");
    printf("-p Number of port\n");
    printf("-T Start encrypting of whole communication (Cannot be used with -S)\n");
    printf("-S Start normal connection and by STLS command become to encryption (Cannot be used with -T)\n");
    printf("-c Define certification file (Can be used with -C)\n");
    printf("-C Define folder of certificates (Can be used with -c)\n");
    printf("-d Delete all messages from server\n");
    printf("-n Download just new emails\n");
    exit(EXIT_SUCCESS);
}


/**
 * Parse an arguments of command line and fill the object of Arguments.
 *
 * @param argc Number of arguments.
 * @param argv Pointer to command line input of arguments.
 */
void parse_args(int argc, char *argv[]){
    int c;
    while ((c = getopt (argc, argv, "hp:a:o:ndTSc:C:")) != -1 ) {
        switch (c) {
            case 'h':
                printHelp();
                break;
            case 'p':
                args->pflag = 1;
                args->port = optarg;
                break;
            case 'a':
                args->aflag = 1;
                args->auth_file = optarg;
                break;
            case 'o':
                args->oflag = 1;
                args->out_dir = optarg;
                break;
            case 'n':
                args->nflag = 1;
                break;
            case 'd':
                args->dflag = 1;
                break;
            case 'T':
                if(args->Sflag == 1){
                    fprintf(stderr,"Parameter S is already used!\n");
                    exit(1);
                }
                args->Tflag = 1;
                break;
            case 'S':
                if(args->Tflag == 1){
                    fprintf(stderr,"Parameter T is already used!\n");
                    exit(1);
                }
                args->Sflag = 1;
                break;
            case 'c':
                if (args->Sflag == 0 && args->Tflag == 0) {
                    fprintf(stderr,"Parameter T or S inst declared!\n");
                    exit(1);
                }
                args->cflag = 1;
                args->certificate = optarg;
                break;
            case 'C':
                if (args->Sflag == 0 && args->Tflag == 0) {
                    fprintf(stderr,"Parameter T or S inst declared!\n");
                    exit(1);
                }
                args->Cflag = 1;
                args->certaddr = optarg;
                break;
            case '?':
                //printf("Unknown argument: %s of %c\n", optarg, c);
                exit(EXIT_FAILURE);
            default:
                break;
        }
    }

    if(optind != argc) {
        args->server_name = argv[optind];
    }

//    printf("Server_name: %s\n", args->server_name);
//    printf ("pflag = %d, port = %s\n", args->pflag, args->port);
//    printf ("aflag = %d, auth_file = %s\n", args->aflag, args->auth_file);
//    printf ("oflag = %d, outdir = %s\n", args->oflag, args->out_dir);
//    printf ("nflag = %d\n", args->nflag);
//    printf ("dflag = %d\n", args->dflag);
//    printf ("Tflag = %d\n", args->Tflag);
//    printf ("Sflag = %d\n", args->Sflag);
//    printf ("cflag = %d, certificate = %s\n", args->cflag, args->certificate);
//    printf ("Cflag = %d, certaddr = %s\n", args->Cflag, args->certaddr);

    if(args->server_name == NULL || args->aflag == 0 || args->oflag == 0){
        fprintf(stderr,"One of compulsory paremeters wanst entered.\nUse popcl -h to print help.\n");
        exit(EXIT_FAILURE);
    }

}


/**
 * Send message to the server.
 *
 * @param client_socket Client Socket
 * @param buffer String of message.
 * @param len Length of message
 * @return Return true when send is succesful or false when sending fails.
 */
bool sendMessage2Server(int client_socket, string buffer, unsigned long len){
    //printf("Client message:%s\n",buffer.c_str());
    ssize_t byteSend;
    if(encryption){
        byteSend = SSL_write(ssl_socket, buffer.c_str(), (int) len);
    }else {
        byteSend = send(client_socket, buffer.c_str(), len, 0);
    }

    if (byteSend < 0) {
        perror("ERROR in sendto");
        return false;
    }
    return true;
}

/**
 * Function recieves first character of message from the server. Used to validate an answer (-/+).
 *
 * @param client_socket Client socket
 * @return Returns string with first character of message.
 */
string recvFirstCharOfMessage2Client(int client_socket){
    char buf[1];
    bzero(buf,1);
    string buffer;
    ssize_t byteRecv;
    if(encryption) {
        byteRecv = SSL_read(ssl_socket,buf, 1);
    } else {
        byteRecv = recv(client_socket, buf, 1, 0);
    }

    if (byteRecv < 0) {
        perror("ERROR in recvfrom");
        exit(EXIT_FAILURE);
    }
    //printf("Server message:%s\n",buf);
    buffer = buf;
    return buffer;
}


/**
 * Function recieves Line messsage from the server.
 *
 * @param client_socket Client socket
 * @return Return string of line message.
 */
string recvLineMessage2Client(int client_socket){
    char buf[BUFSIZE];
    bzero(buf,BUFSIZE);
    string buffer;
    ssize_t byteRecv;
    if(encryption) {
        byteRecv = SSL_read(ssl_socket,buf, BUFSIZE);
    } else {
        byteRecv = recv(client_socket, buf, BUFSIZE, 0); //TODO while \r\n
    }

    if (byteRecv < 0) {
        perror("ERROR in recvfrom");
        exit(EXIT_FAILURE);
    }
    //printf("Server message:%s\n",buf);
    buffer = buf;
    return buffer;
}

/**
 * Function recieves multiline message from the server. End of recieving is indicated by sequence of 5 characters "\r\n.\r\n".
 *
 * @param client_socket Client socket.
 * @return Returns string of multiline message.
 */
string recvMultiLineMessage2Client(int client_socket){
    string buffer;
    char buf[BUFSIZE+1];


    ssize_t byteRecv = -1;
    buffer = "";
    while(true){
        bzero(buf,BUFSIZE+1);
        if(encryption) {
            byteRecv = SSL_read(ssl_socket,buf, BUFSIZE);
        } else {
            byteRecv = recv(client_socket, buf, BUFSIZE, 0); //TODO moznost zrychleni
        }
        if (byteRecv < 0) {
            perror("ERROR in recvfrom");
            exit(EXIT_FAILURE);
        }

        buffer += buf;

        unsigned long len = buffer.length();
        string lastFive;
        if(len >= 5) {
            lastFive = buffer.substr(len - 5, 5);
        }
        if(lastFive == "\r\n.\r\n") {
            break;
        }
    }
    if (byteRecv < 0) {
        perror("ERROR in recvfrom");
        exit(EXIT_FAILURE);
    }

    //printf("Server message(%d,%d):%s\n",(int) byteRecv,(int)buffer.length(),buffer.c_str()); //IN DEBUG 49 chars, IN RELEASE 14
    //printf("___________________________________\n");
    return buffer;

}

/**
 * Log to the server
 *
 * @param client_socket Client socket
 * @return Returns true when logged in or false on fail.
 */
bool logInServer(int client_socket){
    //pop3.seznam.cz  -o maildir -a authfile.txt -p 110
    char username[BUFSIZE-10]; //rezerva pro příkaz 10bytů
    char password[BUFSIZE-10];
    string buffer;

    FILE *authfile = NULL;
    authfile = fopen(args->auth_file,"r");
    if(authfile == NULL){
        perror("Cannot open authentification file.\n");
        return false;
    }
    if(fscanf(authfile, "username = %s\npassword = %s\n", username, password) != 2){
        return false;
    }

    buffer = "USER ";
    buffer.append(username);
    buffer.append("\r\n");
    sendMessage2Server(client_socket, buffer, buffer.length());

    buffer = recvLineMessage2Client(client_socket);
    buffer = buffer.substr(0,1);
    if(!buffer.compare("-")){
        fprintf(stderr,"Bad USERNAME\n");
        return false;
    }

    //No communication
    if(!buffer.compare("")){
        fprintf(stderr,"Error: Connection was not estabilished!\n");
        return false;
    }

    buffer = "PASS ";
    buffer.append(password);
    buffer.append("\r\n");
    sendMessage2Server(client_socket, buffer, buffer.length());

    buffer = recvLineMessage2Client(client_socket);
    buffer = buffer.substr(0,1);
    if(!buffer.compare("-")){
        fprintf(stderr,"Bad PASSWORD\n");
        return false;
    }

    return true;
}

/**
 * Function get list of messages with identification numbers with UIDL or just intialize array size of number messages.
 *
 * @param client_socket Client socket
 * @return Returns array of strings indatificators. First element of array signalized if UIDL works with "+" or not with something else.
 */
vector<string> getListOfMessages(int client_socket){

    string buffer = "UIDL\r\n";
    sendMessage2Server(client_socket,buffer,buffer.length());

    buffer = recvFirstCharOfMessage2Client(client_socket);

    string answerResult = buffer.substr(0,1);
    if(answerResult == "-"){
       recvLineMessage2Client(client_socket); //dump rest of ERR message
        buffer = "LIST\r\n";
        sendMessage2Server(client_socket,buffer,buffer.length());
    }

    buffer = recvMultiLineMessage2Client(client_socket);

    vector<string> listOfId;

   //size_t pos = buffer.find("\r\n");
   // string ids2parse = buffer.substr(pos);

    string line;
    istringstream buffer_stream(buffer);
    while(getline(buffer_stream,line,'\r')) {
        string id = line.substr(line.find(" ") + 1);
        if(line.length() > 2 && line != ".\r\n"){
            //printf("|%s|\n", id.c_str());
            listOfId.push_back(id);
        }

    }
    listOfId[0] = answerResult;

 //   cout << "The contents: ";
//    for(unsigned int i = 0; i < listOfId.size(); i++)
//    {
//       printf("|%s| ", listOfId[i].c_str());
//    }

    return listOfId;
}

/**
 * Delete dots on start of lines. POP3 protocol says that every dot on start of line is doubled so reciever need to delete them.
 *
 * @param buffer Input string of message.
 * @return Message in string without doubled dots at start of line.
 */
string deleteFirstDotInMessageLine(string buffer){
    string cleanMessage = "";
    string c;
    int dotsFound = 0;
    for(unsigned int i = 0; i+dotsFound < buffer.length()-1;i++){
        c = buffer[i];
        cleanMessage.append(c);
        if(buffer[i] == '\n' && buffer[i+1] == '.'){
            i++;
        }
    }
    cleanMessage.append(c);
    return cleanMessage;
}

/**
 * Download one message by server index of message.
 *
 * @param index Index of message
 * @param client_socket Client socket
 * @param listOfId Vector of strings with IDs of messages.
 * @return Returns 1 when message is succesfuly downloaded or 0 when message is already there (only with parameter -n) and -1 on download fail.
 *
 */
int downloadMessage(int index, int client_socket, vector<string> listOfId){
    string id;
    size_t i;

    if(listOfId[0] == "+"){
        i = hash<string>{}(listOfId[index]);
        id = to_string(i);

        if(args->nflag) {
            string path = args->out_dir;
            path.append("/");
            path.append(id);
            FILE *f = fopen(path.c_str(), "r");
            if (f != NULL) {
                fclose(f);
                return 0;
            }
        }
    }

    string buffer = "RETR ";
    buffer.append(to_string(index));
    buffer.append("\r\n");
    sendMessage2Server(client_socket,buffer,buffer.length());

    buffer = recvFirstCharOfMessage2Client(client_socket);

    if(buffer == "-"){
        fprintf(stderr,"Error answer to command RETR %s\n", to_string(index).c_str());
        return -1;
    }

    buffer = recvMultiLineMessage2Client(client_socket);


    size_t pos = buffer.find("\r\n");
    buffer = buffer.substr(pos+2); //\r\n jump over 2 chars

    //printf("Message: %s", buffer.c_str());
    buffer = deleteFirstDotInMessageLine(buffer);

    string path2message = args->out_dir;
    path2message.append("/");


    if(listOfId[0] != "+"){
        //Generate hash for message
        i = hash<string>{}(buffer);
        id = to_string(i);
        //cout<<id <<endl;

        //check existence
        if(args->nflag) {
            string path = args->out_dir;
            path.append("/");
            path.append(id);
            FILE *f = fopen(path.c_str(), "r");
            if (f != NULL) {
                fclose(f);
                return 0;
            }
        }

    }

    path2message.append(id);

    ofstream myFile;
    myFile.open(path2message.c_str());
    if(!myFile.is_open()){
        fprintf(stderr,"Error while opening file (%s)\n", path2message.c_str());
        return -1;
    }
    if(buffer.length() > 5) {
        buffer = buffer.substr(0, buffer.length() - 5);
    }
    myFile << buffer;
    myFile.close();


    return 1;
}


/**
 * Download all messages from server mailbox.
 *
 * @param client_socket Client socket.
 * @param listOfId Vector of strings with IDs of messages.
 * @return Return number of downloaded messages. If fails returns -1.
 */
int downloadAllMessages(int client_socket, vector<string> listOfId){
    unsigned int i = 0;
    int count = 0;
    for(i = 1; i < listOfId.size(); i++){
        int messageState = downloadMessage(i, client_socket, listOfId);
        if(messageState < 0){
            fprintf(stderr, "Error while downloading Message number %d\n",i);
            exit(EXIT_FAILURE);
        } else if (messageState > 0) {
            count++;
        }
    }

    if (i != listOfId.size()) {
        return -1;
    }

    return count;
}

/**
 * Send a command to delete all messages in mailbox.
 *
 * @param client_socket Client socket.
 * @param listOfId Vector of strings with IDs of messages.
 */
void deleteAllMessages(int client_socket, vector<string> listOfId){
    string buffer;
    for(unsigned long i = listOfId.size()-1; 0 < i; i--){
        buffer = "DELE ";
        buffer.append(to_string(i));
        buffer.append("\r\n");
        sendMessage2Server(client_socket,buffer,buffer.length());
    }
}

/**
 * Create a connection between clinet and server.
 *
 * @return Returns client socket.
 */
int createConnection(){
    int client_socket = 0;

    addrinfo hints, *serverInfo, *p;
    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    //Práce s porty
    string port = "110";
    if (args->Tflag == 1){
        port = "995";
    }
    if(args->port != NULL){
        port = args->port;
    }

    // Ziskani adresy serveru pomoci DNS
    if ((getaddrinfo(args->server_name, port.c_str(), &hints, &serverInfo )) != 0){
        fprintf(stderr,"Error: no such host as |%s| on port |%s|\n", args->server_name, port.c_str());
        exit(EXIT_FAILURE);
    }

    int connection = -1;
    for(p = serverInfo; p != NULL; p = p->ai_next){
        /* Vytvoreni soketu */
        if ((client_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) <= 0)
        {
            perror("Error: socket");
            exit(EXIT_FAILURE);
        }
        connection = connect(client_socket, p->ai_addr, p->ai_addrlen);
        if (connection == 0) {
            break;
        }
    }
    if(connection != 0){
        perror("Error: connect:");
        exit(EXIT_FAILURE);
    }

    return client_socket;
}


/**
 * Function turns normal socket to SSL_socket.
 *
 * @param client_socket Client socket.
 * @return Returns SSL_socket or NULL.
 */
SSL* turnSocket2SSL(int client_socket){
    string buffer = "STLS\r\n";
    if(args->Sflag) {
        sendMessage2Server(client_socket, buffer, buffer.length());
        buffer = recvLineMessage2Client(client_socket);
        if(buffer.substr(0,1) == "-"){
            fprintf(stderr, "Command STLS (STARTTLS) is not supported.\n");
            exit(EXIT_FAILURE);
        }
    }

    encryption = true;

    SSL_CTX *ctx;
    SSL_library_init();
    SSL_load_error_strings();     /* load all error messages */
    OpenSSL_add_all_algorithms();   /* load & register cryptos */
    ctx = SSL_CTX_new(SSLv23_client_method());         /* create context */
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);


    long int ret = 0;
    if (args->certificate != NULL && args->certaddr != NULL){
        ret = SSL_CTX_load_verify_locations(ctx, args->certificate, args->certaddr);
    } else if(args->certificate != NULL){
        ret = SSL_CTX_load_verify_locations(ctx, args->certificate, NULL);
    } else if(args->certaddr != NULL){
        ret = SSL_CTX_load_verify_locations(ctx, NULL, args->certaddr);
    }else if(args->certificate == NULL && args->certaddr == NULL){
        ret = SSL_CTX_set_default_verify_paths(ctx);
    }

    if (ret != 1){
        fprintf(stderr,"Error: Certificates not found.\n");
        return NULL;
    }

    ssl_socket = SSL_new(ctx);
    SSL_set_fd(ssl_socket,client_socket);
    int connect = SSL_connect(ssl_socket);
    if (connect != 1) {
        fprintf(stderr,"Error: connection wanst estabilished!\n");
        return NULL;
    }

    X509 *cert = SSL_get_peer_certificate(ssl_socket);
    if(cert == NULL){
        fprintf(stderr,"Error: Server didnt send a certificate.\n");
    }
    //int ret = SSL_CTX_set_default_verify_paths(ctx);

    ret = SSL_get_verify_result(ssl_socket);
    if(X509_V_OK != ret){
        fprintf(stderr,"Error in Certificate validation.\n");
        return NULL;
    }

    return ssl_socket;
}


int main(int argc, char *argv[]) {
    args = new Arguments();
    parse_args(argc, argv);

    int client_socket = createConnection();

    if(!args->Tflag){
        recvLineMessage2Client(client_socket); // Welcome socket from server
    }

    if(args->Tflag || args->Sflag) {
        ssl_socket = turnSocket2SSL(client_socket);
        if (ssl_socket == NULL) {
            printf("Identity of server \"%s\" can not be verified.\n", args->server_name);
            return 2;
        }
    }
    if(args->Tflag) {
        recvLineMessage2Client(client_socket); // Welcome socket from server
    }

    if (!logInServer(client_socket)) {
        fprintf(stderr, "Login to server \"%s\" failed.\n", args->server_name);
        return 1;
    }

    vector<string> listOfId = getListOfMessages(client_socket);


    int countOfMessages = downloadAllMessages(client_socket, listOfId);
    if (!args->nflag) {
        if (countOfMessages < 0) {
            fprintf(stderr, "Error while downloading messages.\n");
            exit(EXIT_FAILURE);
        }
        cout << countOfMessages << " messages downloaded." << endl;
    } else {
        //int countOfMessages = downloadAllNewMessages(client_socket, listOfId);
        cout << countOfMessages << " new messages downloaded." << endl;
    }

    if (args->dflag) {
        deleteAllMessages(client_socket, listOfId);
    }


    //Konec spojení
    string buffer = "QUIT\r\n";
    sendMessage2Server(client_socket, buffer, buffer.length());

    buffer = recvLineMessage2Client(client_socket);
    if(buffer.substr(0,1) == "-"){
        fprintf(stderr,"Error: Changes on the server was not saved!\n");
        return 1;
    }


    //Uvolnění socketu
    if(args->Tflag || args->Sflag) {
        SSL_shutdown(ssl_socket);
        SSL_free(ssl_socket);
    }
    close(client_socket);
    delete args;

    return 0;
}
