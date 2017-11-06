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

/* Constants */
#define MAX_MESSAGE_LENGTH     1025
#define MAX_PORT_FINDING         10
#define MAX_BACKLOG              10
#define MAX_CONNECTIONS        1024
#define TIMEOUT               30000
#define MAX_URL_SPLIT_LENGTH    256
#define MAX_HSPLIT_KEY_LENGTH    64
#define MAX_HSPLIT_VAL_LENGTH   256
#define MAX_QSPLIT_LENGTH        50

/* Types of GET requests */
#define NORMAL 0
#define COLOUR 1
#define TEST 2

/* The certificate file path */
#define CERT_FILE_PATH "./cert.pem"

// A struct to keep info about the connected clients
typedef struct
{
	char *ip;
	int port;
	SSL* ssl;
} ClientInfo;

// Functions for connections and SSL
int OpenListener(int port);
SSL_CTX *InitServerCTX();
void LoadCertificates(SSL_CTX *ctx, char *file);

// Functions declarations
gchar *getCurrentDateTimeAsString();
gchar *getCurrentDateTimeAsISOString();
gchar *getPageStringForGet(gchar *host, gchar *reqURL, char *clientIP, gchar *clientPort, gchar *reqQuery, gchar *colour, int type);
gchar *getPageStringForPost(gchar *host, gchar *reqURL, char *clientIP, gchar *clientPort, gchar *postData);
void logRecvMessage(char *clientIP, gchar *clientPort, gchar *reqMethod, gchar *host, gchar *reqURL, gchar *code);
void sendHeadResponse(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, int per);
void processGetRequest(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, gchar *cookies, int per);
void sendNotFoundResponse(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL);
void processPostRequest(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, gchar *data, int per);
void sendNotImplementedResponce(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL);
void freeHashMap(gpointer key, gpointer value, gpointer user_data);
void printHashMap(gpointer key, gpointer value, gpointer user_data);

int main(int argc, char *argv[])
{
	int port1, port2;
	if (argc < 2)
	{
		g_printf("Format expected is .src/httpd <port_number> <port_number(optional)>\n");
		exit(EXIT_FAILURE);
	}

	if (!(port1 = atoi(argv[1])))
	{
		g_printf("Incorrect format of first port number.\n");
		exit(EXIT_FAILURE);
	}

	if (argc < 3)
	{
		g_printf("Port number for SSL connection missing. We'll try finding one.\n");
		port2 = port1 + 1;
	}
	else {
		if (!(port2 = atoi(argv[2])))
		{
			g_printf("Incorrect format of second (SSL) port number. We'll try finding one.\n");
			port2 = port1 + 1;
		}
	}

	gchar message[MAX_MESSAGE_LENGTH];
	memset(message, 0, sizeof(message));

	int httpSockfd;
	if (!(httpSockfd = OpenListener(port1))) exit(EXIT_FAILURE);
	int numOfOpenPorts = 1;
	int httpsSockfd;
	for (int p = 0; p < MAX_PORT_FINDING; p++)
	{
		if ((httpsSockfd = OpenListener(port2 + p)))
		{
			numOfOpenPorts++;
			break;
		}
	}

	struct sockaddr_in client;
	socklen_t len = (socklen_t)sizeof(client);

	/* The SSL context used for HTTPS connections */
	SSL_CTX *ssl_ctx = NULL; // Initialized to NULL to get rid of compilation warning

	// Setting up structs and variables needed for the poll() function
	struct pollfd pollArray[MAX_CONNECTIONS];
	memset(pollArray, 0, sizeof(pollArray));
	pollArray[0].fd = httpSockfd;
	pollArray[0].events = POLLIN;
	if (numOfOpenPorts > 1)
	{
		pollArray[1].fd = httpsSockfd;
		pollArray[1].events = POLLIN;
		/* Initialize OpenSSL */
		SSL_library_init(); /* load encryption & hash algorithms for SSL */
		ssl_ctx = InitServerCTX();
		LoadCertificates(ssl_ctx, CERT_FILE_PATH); /* load certs */
	}
	else {
		g_printf("Unable to find port for HTTPS\n");
	}

	g_printf("The HTTP port is: %d\nThe HTTPS port is: %d\n", port1, port2);
	g_printf("The HTTP socket is: %d\nThe HTTPS socket is: %d\n", httpSockfd, httpsSockfd);

	/**
	 * We initialize the numOfFds to either 1 or 2, depending if the SSL connection is active or not.
	 * numOfOpenPorts remains the same hereafter!
	 */
	int numOfFds = numOfOpenPorts;

	// Setting up structs to keep info about connected clients
	// Note that the size of clientArray is MAX_CONNECTIONS (and not MAX_CONNECTIONS - 1) for simplicity
	ClientInfo clientArray[MAX_CONNECTIONS];
	memset(clientArray, 0, sizeof(clientArray));

	for (;;)
	{

		for (int i = numOfOpenPorts; i < numOfFds; i++)
		{
			if (pollArray[i].fd == -1)
			{
				for (int j = i; j < numOfFds; j++)
				{
					pollArray[j].fd     = pollArray[j + 1].fd;
					clientArray[j].ip   = clientArray[j + 1].ip;
					clientArray[j].port = clientArray[j + 1].port;
					clientArray[j].ssl  = clientArray[j + 1].ssl;
				}
				numOfFds--;
			}
		}

		// poll() function is used to monitor a set of file descriptors
		int r = poll(pollArray, numOfFds, TIMEOUT);

		if (r < 0)
		{ // This means that the poll() function has encountered an error
			// If the errno is EINTR (interrupt/signal recieved) we go to the start of the for loop again.
			if (errno == EINTR)
				continue;
			// Not interrupted and nothing we can do. Break for loop and exit the program.
			perror("poll() failed");
			break;
		}
		if (r == 0)
		{ // This means that the poll() function timed out
			if (numOfFds > numOfOpenPorts)
			{
				for (int i = numOfOpenPorts; i < numOfFds; i++)
				{ /* Close all persistent connections. */

					if (!clientArray[i].ssl)
					{
						if (send(pollArray[i].fd, "", 0, 0) < 0) perror("send()");
					}
					else
					{
						if (SSL_write(clientArray[i].ssl, "", 0) < 0) perror("SSL_Write()");
					}
					shutdown(pollArray[i].fd, SHUT_RDWR);
					close(pollArray[i].fd);
					if (clientArray[i].ssl) SSL_free(clientArray[i].ssl);
					// Not sure if this is needed. Better safe than sorry...
					memset(&pollArray[i], 0, sizeof(struct pollfd));
					memset(&clientArray[i], 0, sizeof(ClientInfo));
				}
				numOfFds = numOfOpenPorts;
			}
			continue;
		}

		// We've got past the errors and timeouts. So it's either a new
		// connection or activity on one of the open connections.
		for (int i = 0; i < numOfFds; i++)
		{

			// Were there any events for this socket?
			if (!pollArray[i].revents) continue;
			// Is there activity on our HTTP listening socket?
			if (!i)
			{
				// We check if it's a new connection and if we can accept more connections
				if (pollArray[0].revents & POLLIN && numOfFds < MAX_CONNECTIONS)
				{
					memset(&client, 0, sizeof(client));
					// Accepting a TCP connection, pollArray[x].fd is a handle dedicated to this connection.
					if ((pollArray[numOfFds].fd = accept(pollArray[0].fd, (struct sockaddr *)&client, &len)) < 0)
					{
						perror("accept()");
						continue;
					}
					pollArray[numOfFds].events  = POLLIN;
					clientArray[numOfFds].ip    = inet_ntoa(client.sin_addr);
					clientArray[numOfFds].port  = (int)ntohs(client.sin_port);
					clientArray[numOfFds++].ssl = NULL;
				}
				// Either an error occurred or the maximum number of connections has been reached.
				// We might have to handle that but not sure how...
				continue;
			}
			// Is our HTTPS (SSL) listening socket active and is there activity on it?
			if (i < numOfOpenPorts)
			{
				// We check if it's a new connection and if we can accept more connections
				if (pollArray[1].revents & POLLIN && numOfFds < MAX_CONNECTIONS)
				{
					memset(&client, 0, sizeof(client));
					// Accepting a TCP connection, pollArray[x].fd is a handle dedicated to this connection.
					if ((pollArray[numOfFds].fd = accept(pollArray[1].fd, (struct sockaddr *)&client, &len)) < 0)
					{
						perror("accept()");
						continue;
					}
					pollArray[numOfFds].events = POLLIN;
					clientArray[numOfFds].ip = inet_ntoa(client.sin_addr);
					clientArray[numOfFds].port = (int)ntohs(client.sin_port);

					SSL *ssl = SSL_new(ssl_ctx);
					if (ssl == NULL)
					{
						perror("SSL_new()");
						exit(EXIT_FAILURE);
					}
					SSL_set_fd(ssl, pollArray[numOfFds].fd);
					// do SSL-protocol accept
					if (SSL_accept(ssl) < 0)
					{
						perror("SSL_accept()");
						continue;
					}
					clientArray[numOfFds++].ssl = ssl;
				}
				// Either an error occurred or the maximum number of connections has been reached.
				// We might have to handle that but not sure how...
				continue;
			}
			// Is there incoming data on the socket?
			if (pollArray[i].revents & POLLIN)
			{
				ssize_t n;
				if (!clientArray[i].ssl)
				{
					if ((n = recv(pollArray[i].fd, message, sizeof(message) - 1, 0)) < 0) perror("recv()");
				}
				else
				{
					if ((n = SSL_read(clientArray[i].ssl, message, sizeof(message) - 1)) < 0) perror("SSL_read()");
				}

				// In case the recv() function fails (n<0), we close the connection.
				// And if (n=0) the client has closed the connection, we do the same.
				if (n <= 0)
				{
					if (!clientArray[i].ssl)
					{
						if (send(pollArray[i].fd, "", 0, 0) < 0) perror("send()");
					}
					else
					{
						if (SSL_write(clientArray[i].ssl, "", 0) < 0) perror("SSL_Write()");
					}
					shutdown(pollArray[i].fd, SHUT_RDWR);
					close(pollArray[i].fd);
					if (clientArray[i].ssl) SSL_free(clientArray[i].ssl);
					pollArray[i].fd = -1;
					continue;
				}

				// Making sure that the message string is NULL terminated.
				message[n] = '\0';

				// This is used for initial connection tests and debugging
				// Prints out the recieved message as a line of hex characters
				/*for(unsigned int i = 0; i < n; i++) g_printf("%hhx ", message[i]);
				g_printf("\n");*/

				gchar *msgBody         = g_strrstr(message, "\r\n\r\n");
				msgBody[0] = 0; msgBody += 4;
				gchar **msgSplit       = g_strsplit_set(message, "\r\n", 0);
				gchar **firstLineSplit = g_strsplit_set(msgSplit[0], " ", 0);
				GHashTable *hash       = g_hash_table_new(g_str_hash, g_str_equal);

				/* We add 2 each time because there's an empty string between each pair */
				for (unsigned int q = 2; q < g_strv_length(msgSplit); q += 2)
				{
					gchar *tmp1 = g_new0(char, MAX_HSPLIT_KEY_LENGTH);
					gchar *tmp2 = g_new0(char, MAX_HSPLIT_VAL_LENGTH);
					sscanf(msgSplit[q], "%63[^: ]: %255[^\n]", tmp1, tmp2);
					g_hash_table_insert(hash, tmp1, tmp2);
				}
				g_strfreev(msgSplit);

				// For debugging. Iterates through the hash map and prints out each key-value pair
				//g_hash_table_foreach(hash, (GHFunc)printHashMap, NULL);

				gchar *clientPort  = g_strdup_printf("%i", clientArray[i].port);
				gchar *hostField   = g_strdup_printf("%s", (gchar *)g_hash_table_lookup(hash, "Host"));
				gchar **hostSplit  = g_strsplit_set(hostField, ":", 0);
				gchar *connField   = g_strdup_printf("%s", (gchar *)g_hash_table_lookup(hash, "Connection"));
				gchar *cookieField = (gchar *)g_hash_table_lookup(hash, "Cookie");
				gchar *cookies     = NULL;
				if (cookieField) cookies = g_strdup_printf("%s", cookieField);
				g_hash_table_foreach(hash, (GHFunc)freeHashMap, NULL);
				g_hash_table_destroy(hash);

				int persistent = 0;
				if (g_str_has_prefix(firstLineSplit[2], "HTTP/1.0") && g_str_has_prefix(connField, "keep-alive"))
				{
					persistent = 1;
				}
				else if (g_str_has_prefix(firstLineSplit[2], "HTTP/1.1") && !g_str_has_prefix(connField, "close"))
				{
					persistent = 1;
				}
				else if (g_str_has_prefix(firstLineSplit[2], "HTTP/2"))
				{
					persistent = 1;
				}

				if (g_str_has_prefix(message, "HEAD")) // Working with HEAD requests
				{
					sendHeadResponse(pollArray[i].fd, clientArray[i].ssl, clientArray[i].ip, clientPort, hostSplit[0], firstLineSplit[0],
									 firstLineSplit[1], persistent);
				}
				else if (g_str_has_prefix(message, "GET")) // Working with GET requests
				{
					processGetRequest(pollArray[i].fd, clientArray[i].ssl, clientArray[i].ip, clientPort, hostSplit[0], firstLineSplit[0],
									  firstLineSplit[1], cookies, persistent);
				}
				else if (g_str_has_prefix(message, "POST")) // Working with POST requests
				{
					processPostRequest(pollArray[i].fd, clientArray[i].ssl, clientArray[i].ip, clientPort, hostSplit[0], firstLineSplit[0],
									   firstLineSplit[1], msgBody, persistent);
				}
				else // Working with any other (Not implemented/supported) requests
				{
					sendNotImplementedResponce(pollArray[i].fd, clientArray[i].ssl, clientArray[i].ip, clientPort, hostSplit[0],
											   firstLineSplit[0], firstLineSplit[1]);
				}

				if (cookies) g_free(cookies);
				g_free(clientPort); g_free(hostField); g_free(connField);
				g_strfreev(firstLineSplit);
				g_strfreev(hostSplit);
				memset(message, 0, sizeof(message));

				// If it's not a persistent connection, we close it right here
				if (!persistent)
				{
					if (!clientArray[i].ssl)
					{
						if (send(pollArray[i].fd, "", 0, 0) < 0) perror("send()");
					}
					else
					{
						if (SSL_write(clientArray[i].ssl, "", 0) < 0) perror("SSL_Write()");
					}
					shutdown(pollArray[i].fd, SHUT_RDWR);
					close(pollArray[i].fd);
					if (clientArray[i].ssl) SSL_free(clientArray[i].ssl);
					pollArray[i].fd = -1;
				} // else it gets closed when there's a timeout
			}
		}
	}
}

int OpenListener(int port)
{
	/* Create and bind a TCP socket */
	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	/* Network functions need arguments in network byte order instead of
	   host byte order. The macros htonl, htons convert the values. */
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) != 0)
	{
		perror("Unable to bind port");
		return 0;
	}
	/* Before the server can accept messages, it has to listen to the
	   welcome port. A backlog of MAX_BACKLOG connections is allowed. */
	if (listen(sd, MAX_BACKLOG) != 0)
	{
		perror("Unable to configure listening port");
		return 0;
	}
	return sd;
}

SSL_CTX *InitServerCTX()
{
	SSL_CTX *ctx;

	/* Initialize OpenSSL */
	OpenSSL_add_all_algorithms();			   /* load & register all cryptos, etc. */
	SSL_load_error_strings();				   /* load the error strings for good error reporting */
	ctx = SSL_CTX_new(SSLv23_server_method()); /* create new context from method */
	if (!ctx)
	{
		perror("SSL_CTX_new(SSLv23_server_method()) failed");
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *file)
{
	/* Load server certificate into the SSL context */
	if (SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM) <= 0)
	{
		perror("SSL_CTX_use_certificate_file() failed");
		exit(EXIT_FAILURE);
	}

	/* Load the server private-key into the SSL context */
	if (SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM) <= 0)
	{
		perror("SSL_CTX_use_PrivateKey_file() failed");
		exit(EXIT_FAILURE);
	}

	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx))
	{
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
	GDateTime *currTime = g_date_time_new_now_local();
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
 * Creates the pages needed for the GET method
 */
gchar *getPageStringForGet(gchar *host, gchar *reqURL, char *clientIP, gchar *clientPort, gchar *reqQuery, gchar *colour, int type)
{
	gchar *page;
	gchar *firstPart = g_strconcat("<!DOCTYPE html>\n<html>\n<head>\n</head>\n<body", NULL);

	if (type) // Here we create every type of GET page except the 'normal' one
	{
		if (type == TEST) // Creating the 'test' page
		{
			gchar *secondPart = g_strconcat(firstPart, ">\n<p>http://", host, reqURL, " ", clientIP, ":",
											clientPort, "</p>\n", NULL);
			gchar *thirdPart;

			gchar **qSplit = NULL;
			if (*reqQuery)
			{
				qSplit = g_strsplit_set(reqQuery, "&", 0);
			}
			if (qSplit)
			{
				gchar *tmp1 = g_strconcat("<dl>\n<dt>The Queries are:</dt>\n", NULL);
				gchar *tmp2;
				for (unsigned int i = 0; i < g_strv_length(qSplit); i++)
				{
					tmp2 = g_strconcat(tmp1, "<dd>", qSplit[i], "</dd>\n", NULL);
					g_free(tmp1);
					tmp1 = tmp2;
				}
				thirdPart = g_strconcat(secondPart, tmp1, "</dl>\n", NULL);
				g_free(tmp1); g_strfreev(qSplit);
			}
			else
			{
				thirdPart = g_strconcat(secondPart, "<p>No queries found!</p>\n", NULL);
			}

			page = g_strconcat(thirdPart, "</body>\n</html>\n", NULL);
			g_free(secondPart); g_free(thirdPart);
		}
		else { // Creating the 'colour' page
			if (colour)
			{
				page = g_strconcat(firstPart, " style=\"background-color:", colour, "\">\n</body>\n</html>\n", NULL);
			}
			else
			{
				page = g_strconcat(firstPart, ">\n</body>\n</html>\n", NULL);
			}
		}
	}
	else { // The only possibility left is that it's the 'normal' page
		page = g_strconcat(firstPart, ">\n<p>http://", host, reqURL, " ", clientIP, ":", clientPort, "</p>\n",
						   "</body>\n</html>\n", NULL);
	}

	g_free(firstPart);
	return page;
}

/**
 * Creates the page needed for POST method
 */
gchar *getPageStringForPost(gchar *host, gchar *reqURL, char *clientIP, gchar *clientPort, gchar *postData)
{
	gchar *page = g_strconcat("<!DOCTYPE html>\n<html>\n<head>\n</head>\n<body>\n<p>http://", host, reqURL, " ",
							  clientIP, ":", clientPort, "</p>\n", postData, "\n", "</body>\n</html>\n", NULL);
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

	if (fp != NULL)
	{
		fwrite(logMsg, sizeof(char), strlen(logMsg), fp);
		fclose(fp);
	}
	else
	{
		perror("fopen() failed");
	}

	g_free(logMsg); g_free(theTime);
}

/**
 * This function structures a response if a client sends
 * a HEAD request and then sends the response to the client.
 */
void sendHeadResponse(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, int per)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *firstPart = g_strconcat("HTTP/1.1 200 OK\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\n",
								   "Server: TheMagicServer/2.1\r\nConnection: ", NULL);
	gchar *response = per ? g_strconcat(firstPart, "keep-alive\r\n\r\n", NULL) : g_strconcat(firstPart, "close\r\n\r\n", NULL);

	if (!ssl)
	{
		if (send(connfd, response, strlen(response), 0) < 0) perror("send()");
	}
	else
	{
		if (SSL_write(ssl, "", 0) < 0) perror("SSL_Write()");
	}
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "200");
	g_free(theTime); g_free(firstPart); g_free(response);
}

/**
 * This function structures a response if a client sends
 * a GET request and then sends the response to the client.
 */
void processGetRequest(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, gchar *cookies, int per)
{
	gchar *page;
	gchar *reqPage = g_new0(char, MAX_URL_SPLIT_LENGTH);
	gchar *reqQuery = g_new0(char, MAX_URL_SPLIT_LENGTH);
	sscanf(reqURL, "%255[^?]?%255[^\n]", reqPage, reqQuery);

	gchar *theBg = NULL;

	if (!g_strcmp0(reqPage, "/") || !g_strcmp0(reqPage, "/index.html"))
	{
		page = getPageStringForGet(host, reqURL, clientIP, clientPort, reqQuery, NULL, NORMAL);
	}
	else if (!g_strcmp0(reqPage, "/color")  || !g_strcmp0(reqPage, "/colour") ||  // supporting both English and the simplified
			!g_strcmp0(reqPage, "/color/") || !g_strcmp0(reqPage, "/colour/"))    // English versions of the word 'colour'
	{

		gchar **qSplit = NULL;
		if (*reqQuery)
		{
			qSplit = g_strsplit_set(reqQuery, "&", 0);
		}

		GHashTable *qHash = NULL;

		if (cookies)
		{
			gchar **cookieSplit = g_strsplit_set(cookies, "; ", 0);
			qHash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
			for (unsigned int i = 0; i < g_strv_length(cookieSplit); i += 2)
			{
				gchar *tmp1 = g_new0(char, MAX_QSPLIT_LENGTH);
				gchar *tmp2 = g_new0(char, MAX_QSPLIT_LENGTH);
				sscanf(cookieSplit[i], "%49[^=]=%49[^\n]", tmp1, tmp2);
				g_hash_table_insert(qHash, tmp1, tmp2);
			}
			g_strfreev(cookieSplit);
		}

		if (qSplit)
		{
			if (!qHash) qHash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
			for (unsigned int i = 0; i < g_strv_length(qSplit); i++)
			{
				gchar *tmp1 = g_new0(char, MAX_QSPLIT_LENGTH);
				gchar *tmp2 = g_new0(char, MAX_QSPLIT_LENGTH);
				sscanf(qSplit[i], "%49[^=]=%49[^\n]", tmp1, tmp2);
				g_hash_table_insert(qHash, tmp1, tmp2);
			}
			g_strfreev(qSplit);
		}

		
		if (qHash)
		{
			gchar *tmp = (gchar *)g_hash_table_lookup(qHash, "bg");
			if (tmp)
			{
				theBg = g_strdup_printf("%s", tmp);
			}
			g_hash_table_destroy(qHash);
		}

		page = getPageStringForGet(host, reqURL, clientIP, clientPort, reqQuery, theBg, COLOUR);
	}
	else if (!g_strcmp0(reqPage, "/test") || !g_strcmp0(reqPage, "/test/"))
	{
		page = getPageStringForGet(host, reqURL, clientIP, clientPort, reqQuery, NULL, TEST);
	}
	else
	{
		g_free(reqPage); g_free(reqQuery);
		sendNotFoundResponse(connfd, ssl, clientIP, clientPort, host, reqMethod, reqURL);
		return;
	}

	gchar *theTime    = getCurrentDateTimeAsString();
	gchar *contLength = g_strdup_printf("%i", (int)strlen(page));
	gchar *theHeader  = g_strconcat("HTTP/1.1 200 OK\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\nContent-length: ",
									contLength, "\r\nServer: TheMagicServer/2.1\r\n", NULL);

	if (theBg)
	{
		gchar *updateTheHeader = g_strconcat(theHeader, "Set-Cookie: bg=", theBg, "; Path=/colour\r\n",
											 "Set-Cookie: bg=", theBg, "; Path=/color\r\n", NULL);
		g_free(theHeader);
		theHeader = updateTheHeader;
	}

	gchar *response = per ? g_strconcat(theHeader, "Connection: keep-alive\r\n\r\n", page, NULL) :
							g_strconcat(theHeader, "Connection: close\r\n\r\n", page, NULL);

	if (!ssl)
	{
		if (send(connfd, response, strlen(response), 0) < 0) perror("send()");
	}
	else
	{
		if (SSL_write(ssl, response, strlen(response)) < 0) perror("SSL_Write()");
	}
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "200");
	g_free(theTime); g_free(page); g_free(contLength); g_free(theHeader); g_free(response);
	g_free(reqPage); g_free(reqQuery);
	if (theBg) g_free(theBg);
}

/**
 * This function is called if a GET request is sent and
 * anything but the base URL or index.html is requested
 */
void sendNotFoundResponse(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *response = g_strconcat("HTTP/1.1 404 Not Found\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\n",
								  "Content-length: 0\r\nServer: TheMagicServer/2.1\r\nConnection: close\r\n\r\n", NULL);

	if (!ssl)
	{
		if (send(connfd, response, strlen(response), 0) < 0) perror("send()");
	}
	else
	{
		if (SSL_write(ssl, response, strlen(response)) < 0) perror("SSL_Write()");
	}
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "404");
	g_free(theTime); g_free(response);
}

/**
 * This function handles POST requests. It simply gets a string for the page
 * to be returned with the requested text being added into the <body> tag.
 */
void processPostRequest(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL, gchar *data, int per)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *page = getPageStringForPost(host, reqURL, clientIP, clientPort, data);
	gchar *contLength = g_strdup_printf("%i", (int)strlen(page));
	gchar *theHeader = g_strconcat("HTTP/1.1 201 OK\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\nContent-length: ",
								   contLength, "\r\nServer: TheMagicServer/2.1\r\nConnection: ", NULL);
	gchar *response = per ? g_strconcat(theHeader, "keep-alive\r\n\r\n", page, NULL) : g_strconcat(theHeader, "close\r\n\r\n", page, NULL);

	if (!ssl)
	{
		if (send(connfd, response, strlen(response), 0) < 0) perror("send()");
	}
	else
	{
		if (SSL_write(ssl, response, strlen(response)) < 0) perror("SSL_Write()");
	}
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "201");
	g_free(theTime); g_free(page); g_free(theHeader); g_free(response);
}

/**
 * This function handles requests that are not supported, i.e. requests NOT of type GET, HEAD or POST
 */
void sendNotImplementedResponce(int connfd, SSL *ssl, char *clientIP, gchar *clientPort, gchar *host, gchar *reqMethod, gchar *reqURL)
{
	gchar *theTime = getCurrentDateTimeAsString();
	gchar *response = g_strconcat("HTTP/1.1 501 Not Implemented\r\nDate: ", theTime, "\r\nContent-Type: text/html\r\n",
								  "Content-length: 0\r\nServer: TheMagicServer/2.1\r\nConnection: close\r\n\r\n", NULL);
	if (!ssl)
	{
		if (send(connfd, response, strlen(response), 0) < 0) perror("send()");
	}
	else
	{
		if (SSL_write(ssl, response, strlen(response)) < 0) perror("SSL_Write()");
	}
	logRecvMessage(clientIP, clientPort, reqMethod, host, reqURL, "501");
	g_free(response); g_free(theTime);
}

/**
 * This function is used to free all the strings used for the
 * hashmap that contains all the header fields and values
 */
void freeHashMap(gpointer key, gpointer value, gpointer G_GNUC_UNUSED user_data)
{
	g_free(key); g_free(value);
}

/**
 * This function is used to help with debugging. It's passed as a GHFunc to the
 * g_hash_table_foreach function and prints out each (key, value) in a hash map
 */
void printHashMap(gpointer key, gpointer value, gpointer G_GNUC_UNUSED user_data)
{
	g_printf("The key is \"%s\" and the value is \"%s\"\n", (char *)key, (char *)value);
}
