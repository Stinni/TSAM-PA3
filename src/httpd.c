// HTTP Server 2 - Programming Assignment 3 for Computer Networking
// Built on top of PA2 - HTTP Server
// University of Reykjavík, autumn 2017
// Students: Hreiðar Ólafur Arnarsson, Kristinn Heiðar Freysteinsson & Maciej Sierzputowski
// Usernames: hreidara14, kristinnf13 & maciej15

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <errno.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

// Constants:
#define MAX_MESSAGE_LENGTH  1025
#define MAX_BACKLOG           10
#define MAX_CONNECTIONS     1024
#define TIMEOUT             6000 // TODO: CHANGE THIS BEFORE HANDIN!!!

// A struct to keep info about the connected clients
typedef struct {
	char *ip;
	int port;
} ClientInfo;

// SSL functions
int OpenListener(int port);
SSL_CTX* InitServerCTX();
void LoadCertificates(SSL_CTX* ctx, char* file);

// Functions declarations
gchar *getCurrentDateTimeAsString();
gchar *getCurrentDateTimeAsISOString();
gchar *getPageString(gchar *host, gchar *reqURL, char *clientIP, gchar *clientPort, gchar *data);
void logRecvMessage(char *clientIP, gchar *clientPort, gchar *reqMethod, gchar *host, gchar *reqURL, gchar *code);
void sendHeadResponse(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, int per);
void processGetRequest(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, int per);
void sendNotFoundResponse(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL);
void processPostRequest(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, gchar *data, int per);
void sendNotImplementedResponce(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL);
void printHashMap(gpointer key, gpointer value, gpointer user_data);

int main(int argc, char *argv[])
{
	if(argc < 2) {
		g_printf("Format expected is .src/httpd <port_number>\n");
		exit(EXIT_SUCCESS);
	}

	gchar message[MAX_MESSAGE_LENGTH];
	memset(message, 0, sizeof(message));

	/* Create and bind a TCP socket */
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	/* Network functions need arguments in network byte order instead of
	   host byte order. The macros htonl, htons convert the values. */
	struct sockaddr_in server, client;
	socklen_t len = (socklen_t) sizeof(client);
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(atoi(argv[1]));
	bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

	/* Before the server can accept messages, it has to listen to the
	   welcome port. A backlog of MAX_BACKLOG connections is allowed. */
	listen(sockfd, MAX_BACKLOG);

	// Setting up structs and variables needed for the poll() function
	struct pollfd pollArray[MAX_CONNECTIONS];
	int numOfFds = 1;
	memset(pollArray, 0, sizeof(pollArray));
	pollArray[0].fd = sockfd;
	pollArray[0].events = POLLIN;

	// Setting up structs to keep info about connected clients
	// Note that the size of clientArray is MAX_CONNECTIONS (and not MAX_CONNECTIONS-1) for simplicity
	ClientInfo clientArray[MAX_CONNECTIONS];
	memset(clientArray, 0, sizeof(clientArray));

	for(;;) {

		for(int i = 1; i < numOfFds; i++) {
			if(pollArray[i].fd == -1) {
				for(int j = i; j < numOfFds; j++) {
					pollArray[j].fd     = pollArray[j+1].fd;
					clientArray[j].ip   = clientArray[j+1].ip;
					clientArray[j].port = clientArray[j+1].port;
				}
				numOfFds--;
			}
		}

		// poll() function is used to monitor a set of file descriptors
		int r = poll(pollArray, numOfFds, TIMEOUT);

		if(r < 0) { // This means that the poll() function has encountered an error
			// If the errno is EINTR (interrupt/signal recieved) we go to the start of the for loop again.
			if(errno == EINTR) continue;
			// Not interrupted and nothing we can do. Break for loop and exit the program.
			perror("poll() failed");
			break;
		}
		if(r == 0) { // This means that the poll() function timed out
			if(numOfFds > 1) {
				for(int i = 1; i < numOfFds; i++) { /* Close all persistent connections. */
					send(pollArray[i].fd, "", 0, 0);
					shutdown(pollArray[i].fd, SHUT_RDWR);
					close(pollArray[i].fd);
					// Not sure if this is needed. Better safe than sorry...
					memset(&pollArray[i], 0, sizeof(struct pollfd));
					memset(&clientArray[i], 0, sizeof(ClientInfo));
				}
				numOfFds = 1;
			}
			continue;
		}

		// We've got past the errors and timeouts. So it's either a new
		// connection or activity on one of the open connections.
		for(int i = 0; i < numOfFds; i++) {

			// Were there any events for this socket?
			if(!pollArray[i].revents) continue;
			// Is there activity on our listening socket?
			if(!i) {
				// We check if it's a new connection and if we can accept more connections
				if(pollArray[0].revents & POLLIN && numOfFds < MAX_CONNECTIONS) {
					// Accepting a TCP connection, pollArray[x].fd is a handle dedicated to this connection.
					pollArray[numOfFds].fd       = accept(sockfd, (struct sockaddr *) &client, &len);
					pollArray[numOfFds].events   = POLLIN;
					clientArray[numOfFds].ip     = inet_ntoa(client.sin_addr);
					clientArray[numOfFds++].port = (int)ntohs(client.sin_port);
				}
				else {
					// Either an error occurred or the maximum number of connections has been reached.
					// We might have to handle that but not sure how...
				}
				continue;
			}
			// Is there incoming data on the socket?
			if(pollArray[i].revents & POLLIN) {
				ssize_t n = recv(pollArray[i].fd, message, sizeof(message) - 1, 0);

				// In case the recv() function fails (n<0), we close the connection.
				// And if (n=0) the client has closed the connection, we do the same.
				if(n <= 0) {
					send(pollArray[i].fd, "", 0, 0);
					shutdown(pollArray[i].fd, SHUT_RDWR);
					close(pollArray[i].fd);
					pollArray[i].fd = -1;
					continue;
				}

				// Making sure that the message string is NULL terminated.
				message[n] = '\0';

				// This is used for initial connection tests and debugging
				// Prints out the recieved message as a line of hex characters
				/*for(unsigned int i = 0; i < n; i++) g_printf("%hhx ", message[i]);
				g_printf("\n");*/

				gchar *msgBody     = g_strrstr(message, "\r\n\r\n\0");
				msgBody[0] = 0; msgBody += 4;
				gchar **msgSplit   = g_strsplit_set(message, " \r\n", 0);
				gchar *httpVersion = g_strrstr(message, "HTTP");

				GHashTable *hash = g_hash_table_new(g_str_hash, g_str_equal);
				/* We deduct 1 from g_strv_length because we count from 0 */
				/* And we add 3 each time because there're empty strings in between each pair */
				if(msgSplit != NULL) {
					for(unsigned int q = 4; q < g_strv_length(msgSplit) - 1; q += 3) {
						g_hash_table_insert(hash, msgSplit[q], msgSplit[q+1]);
					}
				}

				char page[100], query[100];
				memset(page, 0, sizeof(page)); memset(query, 0, sizeof(query));
				sscanf(msgSplit[1], "/%99[^?]?%99[^\n]", page, query);
				printf("The requested page is: %s\n", page);
				if(*query) {
					gchar **qSplit = g_strsplit_set(query, "&", 0);
					for(unsigned int j = 0; j < g_strv_length(qSplit); j++) {
						char tmp1[30]; memset(tmp1, 0, sizeof(tmp1));
						char tmp2[30]; memset(tmp2, 0, sizeof(tmp2));
						sscanf(qSplit[j], "%99[^=]=%99[^\n]", tmp1, tmp2);
						g_printf("query %d is: %s\n", j+1, qSplit[j]);
						g_printf("second part of that is: %s\n", tmp2);
					}
					g_strfreev(qSplit);
				}

				// For debugging. Iterates through the hash map and prints out each key-value pair
				//g_hash_table_foreach(hash, (GHFunc)printHashMap, NULL);

				gchar *clientPort = g_strdup_printf("%i", clientArray[i].port);
				gchar *hostField  = g_strdup_printf("%s", (gchar *)g_hash_table_lookup(hash, "Host:"));
				gchar **hostSplit = g_strsplit_set(hostField, ":", 0);
				gchar *connField  = g_strdup_printf("%s", (gchar *)g_hash_table_lookup(hash, "Connection:"));

				int persistent = 0;
				if(g_str_has_prefix(httpVersion, "HTTP/1.0") && g_str_has_prefix(connField, "keep-alive")) {
					persistent = 1;
				}
				else if(g_str_has_prefix(httpVersion, "HTTP/1.1") && !g_str_has_prefix(connField, "close")) {
					persistent = 1;
				}
				else if(g_str_has_prefix(httpVersion, "HTTP/2")) {
					persistent = 1;
				}

				if(g_str_has_prefix(message, "HEAD")) { // Working with HEAD requests
					sendHeadResponse(pollArray[i].fd, clientArray[i].ip, clientPort, hostSplit[0], msgSplit[0],
									 msgSplit[1], persistent);
				}
				else if(g_str_has_prefix(message, "GET")) { // Working with GET requests
					if(!g_strcmp0(msgSplit[1], "/") || !g_strcmp0(msgSplit[1], "/index.html")) {
						processGetRequest(pollArray[i].fd, clientArray[i].ip, clientPort, hostSplit[0], msgSplit[0],
										  msgSplit[1], persistent);
					}
					else {
						sendNotFoundResponse(pollArray[i].fd, clientArray[i].ip, clientPort, hostSplit[0], msgSplit[0],
											 msgSplit[1]);
					}
				}
				else if(g_str_has_prefix(message, "POST")) { // Working with POST requests
					processPostRequest(pollArray[i].fd, clientArray[i].ip, clientPort, hostSplit[0], msgSplit[0],
									   msgSplit[1], msgBody, persistent);
				}
				else { // Working with any other (Not implemented/supported) requests
					sendNotImplementedResponce(pollArray[i].fd, clientArray[i].ip, clientPort, hostSplit[0],
											   msgSplit[0], msgSplit[1]);
				}

				g_free(clientPort); g_free(hostField); g_free(connField);
				g_strfreev(msgSplit); g_strfreev(hostSplit);
				g_hash_table_destroy(hash);
				memset(message, 0, sizeof(message));

				// If it's not a persistent connection, we close it right here
				if(!persistent) {
					send(pollArray[i].fd, "", 0, 0);
					shutdown(pollArray[i].fd, SHUT_RDWR);
					close(pollArray[i].fd);
					pollArray[i].fd = -1;
				} // else it gets closed when there's a timeout
			}
		}
	}
}

int OpenListener(int port)
{
	int sd;
	struct sockaddr_in addr;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sd, (struct sockaddr*) &addr, (socklen_t) sizeof(addr)) != 0)
	{
		perror("Unable to bind port");
		exit(EXIT_FAILURE);
	}
	if(listen(sd, MAX_CONNECTIONS) != 0 ) // A backlog of MAX_CONNECTIONS connections is allowed
	{
		perror("Unable to configure listening port");
		exit(EXIT_FAILURE);
	}
	return sd;
}

SSL_CTX* InitServerCTX()
{
	SSL_CTX *ctx;

	/* Initialize OpenSSL */
	OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
	SSL_load_error_strings(); /* load the error strings for good error reporting */
	ctx = SSL_CTX_new(SSLv23_server_method()); /* create new context from method */
	if(!ctx)
	{
		perror("SSL_CTX_new(SSLv23_server_method()) failed");
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* file)
{
	/* Load server certificate into the SSL context */
	if(SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM) <= 0) { 
		perror("SSL_CTX_use_certificate_file() failed");
		exit(EXIT_FAILURE);
	}

	/* Load the server private-key into the SSL context */
	if(SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM) <= 0) {
		perror("SSL_CTX_use_PrivateKey_file() failed");
		exit(EXIT_FAILURE);
	}

	/* verify private key */
	if(!SSL_CTX_check_private_key(ctx)) {
		perror("Private key does not match the public certificate\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * The function gets the current date and time, custom formats it and then returns it.
 * It's used for the responses that're sent.
 */
gchar *getCurrentDateTimeAsString()
{
	GDateTime *currTime  = g_date_time_new_now_local();
	gchar *dateAsString = g_date_time_format(currTime, "%a, %d %b %Y %H:%M:%S %Z");
	g_date_time_unref(currTime);
	return dateAsString;
}

/**
 * The function gets the current date and time, and then returns it in the ISO 8601 format.
 * It's only used for the logging of requests
 */
gchar *getCurrentDateTimeAsISOString()
{
	GTimeVal theTime;
	g_get_current_time(&theTime);
	return g_time_val_to_iso8601(&theTime);
}

/**
 * creates the page needed for GET and POST methods. Data is NULL for a GET request.
 */
gchar *getPageString(gchar *host, gchar *reqURL, char *clientIP, gchar *clientPort, gchar *data)
{
	gchar *page;
	gchar *firstPart = g_strconcat("<!DOCTYPE html>\n<html>\n<head>\n</head>\n<body>\n<p>http://", host, reqURL,
								   " ", clientIP, ":", clientPort, "</p>\n", NULL);
	gchar *lastPart = g_strconcat("</body>\n</html>\n", NULL);
	if(data != NULL) {
		page = g_strconcat(firstPart, data, "\n", lastPart, NULL);
	} else {
		page = g_strconcat(firstPart, lastPart, NULL);
	}
	g_free(firstPart); g_free(lastPart);
	return page;
}

/**
 * This function writes client requests the server receives to a log file.
 * It writes the date and time, the client's IP and port numbers, the type
 * of request, the requested URL and the response the server gave the client.
 */
void logRecvMessage(char *clientIP, gchar *clientPort, gchar *reqMethod, gchar *host, gchar *reqURL, gchar *code)
{
	gchar *theTime = getCurrentDateTimeAsISOString();
	gchar *logMsg = g_strconcat(theTime, " : ", clientIP, ":", clientPort, " ", reqMethod, " ", host, reqURL, " : ", code, "\n", NULL);

	FILE *fp;
	fp = fopen("log.txt", "a");

	if(fp != NULL) {
		fwrite(logMsg, sizeof(char), strlen(logMsg), fp);
		fclose(fp);
	} else {
		perror("fopen() failed");
	}

	g_free(logMsg);
	g_free(theTime);
}

/**
 * This function structures a response if a client sends
 * a HEAD request and then sends the response to the client.
 */
void sendHeadResponse(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, int per)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *firstPart = g_strconcat("HTTP/1.1 200 OK\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\n",
								  "Server: TheMagicServer/2.1\r\nConnection: ", NULL);
	gchar *response;
	if(per) {
		response = g_strconcat(firstPart, "keep-alive\r\n\r\n", NULL);
	}
	else {
		response = g_strconcat(firstPart, "close\r\n\r\n", NULL);
	}

	send(connfd, response, strlen(response), 0);
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "200");
	g_free(theTime); g_free(firstPart); g_free(response);
}

/**
 * This function structures a response if a client sends
 * a GET request and then sends the response to the client.
 */
void processGetRequest(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, int per)
{
	gchar *theTime = getCurrentDateTimeAsString();
	//if color page do below
	//check if there is a cookie for clientIP and it is not timed out
	//gchar *page = g_strconcat("<!DOCTYPE html>\n<html>\n<head>\n</head>\n<body style="background-color:",
	//bg[0],"></body>\n</html>\n",NULL);
	//else if test page
	//gchar *page = getPageString(host, reqURL, clientIP, clientPort, queryData);
	//else
	gchar *page = getPageString(host, reqURL, clientIP, clientPort, NULL);
	gchar *contLength = g_strdup_printf("%i", (int)strlen(page));
	gchar *firstPart = g_strconcat("HTTP/1.1 200 OK\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\nContent-length: ",
								  contLength, "\r\nServer: TheMagicServer/2.1\r\nConnection: ", NULL);
	gchar *response;
	if(per) {
		response = g_strconcat(firstPart, "keep-alive\r\n\r\n", page, NULL);
	}
	else {
		response = g_strconcat(firstPart, "close\r\n\r\n", page, NULL);
	}

	send(connfd, response, strlen(response), 0);
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "200");
	g_free(theTime); g_free(page); g_free(contLength); g_free(firstPart); g_free(response);
}

/**
 * This function is called if a GET request is sent and
 * anything but the base URL or index.html is requested
 */
void sendNotFoundResponse(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *response = g_strconcat("HTTP/1.1 404 Not Found\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\n",
								  "Content-length: 0\r\nServer: TheMagicServer/2.1\r\nConnection: close\r\n\r\n", NULL);

	send(connfd, response, strlen(response), 0);
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "404");
	g_free(theTime); g_free(response);
}

/**
 * This function handles POST requests. It simply gets a string for the page
 * to be returned with the requested text being added into the <body> tag.
 */
void processPostRequest(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, gchar *data, int per)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *page = getPageString(host, reqURL, clientIP, clientPort, data);
	gchar *contLength = g_strdup_printf("%i", (int)strlen(page));
	gchar *firstPart = g_strconcat("HTTP/1.1 201 OK\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\nContent-length: ",
								  contLength, "\r\nServer: TheMagicServer/2.1\r\nConnection: ", NULL);
	gchar *response;
	if(per) {
		response = g_strconcat(firstPart, "keep-alive\r\n\r\n", page, NULL);
	}
	else {
		response = g_strconcat(firstPart, "close\r\n\r\n", page, NULL);
	}

	send(connfd, response, strlen(response), 0);
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "201");
	g_free(theTime); g_free(page); g_free(firstPart); g_free(response);
}

/**
 * This function handles requests that are not supported, i.e. requests NOT of type GET, HEAD or POST
 */
void sendNotImplementedResponce(int connfd, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *response = g_strconcat("HTTP/1.1 501 Not Implemented\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\n",
								  "Content-length: 0\r\nServer: TheMagicServer/2.1\r\nConnection: close\r\n\r\n", NULL);
	send(connfd, response, strlen(response), 0);
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "501");
	g_free(theTime);
	g_free(response);
}

/**
 * This function is used to help with debugging. It's passed as a GHFunc to the
 * g_hash_table_foreach function and prints out each (key, value) in a hash map
 */
void printHashMap(gpointer key, gpointer value, gpointer G_GNUC_UNUSED user_data) {
	g_printf("The key is \"%s\" and the value is \"%s\"\n", (char *)key, (char *)value);
}


/**
 * This function processes queries
 * Checks validity of queries, are queries always on the form ?test=1 or can they
 * be different?
 */
void processQueryRequests() {}

/**
 * This function takes in query items and creates a page that is displayed client side
 * when client asks for http://localhost/test with one or more queries
 * If called with no query then a normal GET request is used
 */

 // það væri hægt að smíða þetta beint inn í getrequests með tjékki á getURL?
 // ættu loggarnir líka að taka á queries?
void processTestPageRequests() {

}

/**
 * This function is used when client asks for http://localhost/color, it builds the webpage
 * and returns it to the user based on the value in the bg query.
 * Additionally, it creates a colour cookie that the server uses to remember last colour
 * request from the client.
 */
void processColorPageRequests() {

} 

/**
 * Pseudocode
 * parse url so that we've got what comes after / in http:/localhost/skjfsls
 * if it is TEST or COLOR we take action otherwise continue with a normal GET request
 * if it is TEST we parse to see if there are any query parameters (might even do that
 * beforehand and keep track of it with a true/false variable)
 * the queries are parsed into a map
 * we send the query parameters into a function for TEST that creates the necessary body for the page
 * (might just use it as a return value)
 * we then build the page as a normal GET request
 * if the page request is COLOR then we also have a GET request except(!) the page we send back
 * to client should not have any text on it, only change the style of the body to use the color of
 * the bg query (or rather, add style="background-color:<value-of-bg>") to <body> even if the value of
 * bg is not a color (it will just show an empty page with no color)
 */

 /**
  * Can query be on the form ?2001-09-11
  * According to Piazza server should react to malformed queries with an error instead of crashing.
  * It should send error 405.
  */

/**
 * Maybe getPageString should take in an extra variable for string?
 * or... maybe we can just do all the necessary coding in getPageString?
 * because all queries should be doing is adding or changing the contents of the website
 * aka the page string, we already send in the requested URL to the function so
 * it makes sense to have all calls to parsing and building the page logic in there
 */