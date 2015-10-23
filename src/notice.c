


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT "5061"   // port we're listening on
#define MAX_REG 100

struct registration{
  int socketfd;
  char user[128];
};

struct registration registrations[MAX_REG];
int numRegistered;


struct registration* findUser(char* user)
{
  int i;

  for(i=0; i<MAX_REG;i++){
    if(strncmp(user, registrations[i].user, 128)==0){
      return &registrations[i];
    }
  }
  return NULL;
}

int registerUser(char *user, int socket)
{
  struct registration *reg;
  reg = findUser(user);

  if( reg != NULL){
    return 403;
  }

  if( numRegistered < MAX_REG){
    registrations[numRegistered].socketfd= socket;

    strncpy(registrations[numRegistered].user,
            user, strlen(user));
    numRegistered++;
    printf("Registered user %s on socket %i\n", user, socket);
    return 200;
  }
  return 403;
}

int inviteUser(char *user, char *msg, int msg_len)
{
  struct registration *reg;
  reg = findUser(user);

  if(user != NULL){
    printf("User found! on socket: %i\n %s\n", reg->socketfd, msg);
    if (send(reg->socketfd, msg, msg_len, 0) == -1) {
      perror("Invite send");
    }
  return 100;

  }
  else{
    printf("No user found (%s)\n", user);
    return 404;
  }
}

int handle200Ok(char *msg, int msg_len)
{
  char str[255];
  char *delim = "\n:\\";
  char *tok;
  int i;

 if(msg_len>255) return -1;

  strncpy(str, msg, 255);

  tok = strtok((char *)str, delim);
  //Pesky parsing again
  //Find the to tags
  while(tok != NULL){
    printf("tok: %s\n", tok);

    if( strncmp(tok, "To", 3) == 0){
      tok = strtok(NULL, delim);
      while( isspace(*tok)) tok++;
      printf("Found the To tag (%s)\n", tok);
      for(i=0; i<MAX_REG;i++){
        if(strncmp(tok, registrations[i].user, 128)==0){
          printf("User found! on socket: %i\n %s\n", registrations[i].socketfd, msg);

          if (send(registrations[i].socketfd, msg, msg_len, 0) == -1) {
              perror("Invite send");
            }

          return 100;
        }
      }

    }
    tok = strtok(NULL, delim);
  }
  return 1;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
    fd_set master;    // master file descriptor list
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number

    int listener;     // listening socket descriptor
    int newfd;        // newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen;

    char buf[512];    // buffer for client data
    int nbytes;

    char remoteIP[INET6_ADDRSTRLEN];

    int yes=1;        // for setsockopt() SO_REUSEADDR, below
    int i, rv;

    struct addrinfo hints, *ai, *p;

    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);

    numRegistered = 0;

    // get us a socket and bind it
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(NULL, PORT, &hints, &ai)) != 0) {
        fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
        exit(1);
    }

    for(p = ai; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) {
            continue;
        }

        // lose the pesky "address already in use" error message
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            continue;
        }

        break;
    }

    // if we got here, it means we didn't get bound
    if (p == NULL) {
        fprintf(stderr, "selectserver: failed to bind\n");
        exit(2);
    }

    freeaddrinfo(ai); // all done with this

    // listen
    if (listen(listener, 10) == -1) {
        perror("listen");
        exit(3);
    }

    // add the listener to the master set
    FD_SET(listener, &master);

    // keep track of the biggest file descriptor
    fdmax = listener; // so far, it's this one

    // main loop
    for(;;) {
        read_fds = master; // copy it
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(4);
        }

        // run through the existing connections looking for data to read
        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if (i == listener) {
                    // handle new connections
                    addrlen = sizeof remoteaddr;
                    newfd = accept(listener,
                        (struct sockaddr *)&remoteaddr,
                        &addrlen);

                    if (newfd == -1) {
                        perror("accept");
                    } else {
                        FD_SET(newfd, &master); // add to master set
                        if (newfd > fdmax) {    // keep track of the max
                            fdmax = newfd;
                        }
                        printf("selectserver: new connection from %s on "
                            "socket %d\n",
                            inet_ntop(remoteaddr.ss_family,
                                get_in_addr((struct sockaddr*)&remoteaddr),
                                remoteIP, INET6_ADDRSTRLEN),
                            newfd);
                    }
                } else {
                    // handle data from a client
                    if ((nbytes = recv(i, buf, sizeof buf, 0)) <= 0) {
                        // got error or connection closed by client
                        if (nbytes == 0) {
                            // connection closed
                            printf("selectserver: socket %d hung up\n", i);
                        } else {
                            perror("recv");
                        }
                        close(i); // bye!
                        FD_CLR(i, &master); // remove from master set
                    } else {
                        // we got some data from a client
                        if(strncmp(buf, "REGISTER", 8) == 0 ){
                          int ret;

                          ret = registerUser(buf+9, i);

                          //memset(buf, 0, sizeof buf);
                          if (ret == 200){
                            if (send(i, "200 OK", 6, 0) == -1) {
                                perror("send");
                              }
                          }else{
                            if (send(i, "401", 3, 0) == -1) {
                                perror("send");
                              }
                          }
												}
                        if(strncmp(buf, "INVITE", 6) == 0 ){
                          int ret;
                          char str[sizeof buf];
                          strncpy(str, buf, sizeof buf);
                          const char delim[2] ="\n";
                          printf("buf: \n %s\n", buf);
                          ret =inviteUser(strtok(str+7, delim), buf, strlen(buf));

                          //memset(buf, 0, sizeof buf);
                          if (ret == 100){
                            if (send(i, "100 Trying", 10, 0) == -1) {
                                perror("send");
                            }
                          }else{
                            if (send(i, "404", 3, 0) == -1) {
                                perror("send");
                              }
                          }
												}
                        if(strncmp(buf, "200 OK", 6) == 0 ){
                          printf("Got a 200 OK: %s\n", buf);
                          handle200Ok(buf, nbytes);

												}
                        /*for(j = 0; j <= fdmax; j++) {
                            // send to everyone!
                            if (FD_ISSET(j, &master)) {
                                // except the listener and ourselves
                                if (j != listener && j != i) {
                                    if (send(j, buf, nbytes, 0) == -1) {
                                        perror("send");
                                    }
                                }
                            }
                        }*/
                        memset(buf, 0, sizeof buf);
                    }
                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END for(;;)--and you thought it would never end!

    return 0;
}

	#if 0
	int verify_peer = ON;
	const SSL_METHOD *server_meth;
	SSL_CTX *ssl_server_ctx;
	int serversocketfd;
	int clientsocketfd;
	struct sockaddr_un serveraddr;
	//int handshakestatus;

	SSL_library_init();
	SSL_load_error_strings();
	server_meth = SSLv3_server_method();
	ssl_server_ctx = SSL_CTX_new(server_meth);

	if(!ssl_server_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(SSL_CTX_use_certificate_file(ssl_server_ctx, SSL_SERVER_RSA_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if(SSL_CTX_use_PrivateKey_file(ssl_server_ctx, SSL_SERVER_RSA_KEY, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(SSL_CTX_check_private_key(ssl_server_ctx) != 1)
	{
		printf("Private and certificate is not matching\n");
		return -1;
	}

	if(verify_peer)
	{
		//See function man pages for instructions on generating CERT files
		if(!SSL_CTX_load_verify_locations(ssl_server_ctx, SSL_SERVER_RSA_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}
		SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_server_ctx, 1);
	}

	if((serversocketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Error on socket creation\n");
		return -1;
	}
	memset(&serveraddr, 0, sizeof(struct sockaddr_un));
	serveraddr.sun_family = AF_UNIX;
	serveraddr.sun_path[0] = 0;
	strncpy(&(serveraddr.sun_path[1]), SSL_SERVER_ADDR, strlen(SSL_SERVER_ADDR) + 1);
	if(bind(serversocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un)))
	{
		printf("server bind error\n");
		return -1;
	}

	if(listen(serversocketfd, SOMAXCONN))
	{
		printf("Error on listen\n");
		return -1;
	}
	while(1)
	{
		SSL *serverssl;
		char buffer[1024];
		int bytesread = 0;
		int addedstrlen;
		int ret;

		clientsocketfd = accept(serversocketfd, NULL, 0);
		serverssl = SSL_new(ssl_server_ctx);
		if(!serverssl)
		{
			printf("Error SSL_new\n");
			return -1;
		}
		SSL_set_fd(serverssl, clientsocketfd);

		if((ret = SSL_accept(serverssl))!= 1)
		{
			printf("Handshake Error %d\n", SSL_get_error(serverssl, ret));
			return -1;
		}

		if(verify_peer)
		{
			X509 *ssl_client_cert = NULL;

			ssl_client_cert = SSL_get_peer_certificate(serverssl);

			if(ssl_client_cert)
			{
				long verifyresult;

				verifyresult = SSL_get_verify_result(serverssl);
				if(verifyresult == X509_V_OK)
					printf("Certificate Verify Success\n");
				else
					printf("Certificate Verify Failed\n");
				X509_free(ssl_client_cert);
			}
			else
				printf("There is no client certificate\n");
		}
		bytesread = SSL_read(serverssl, buffer, sizeof(buffer));
		addedstrlen = strlen("Appended by SSL server");
		strncpy(&buffer[bytesread], "Appended by SSL server", addedstrlen);
		buffer[bytesread +  addedstrlen ] = '\0';
		SSL_write(serverssl, buffer, bytesread + addedstrlen + 1);
		SSL_shutdown(serverssl);
		close(clientsocketfd);
		clientsocketfd = -1;
		SSL_free(serverssl);
		serverssl = NULL;
	}
	close(serversocketfd);
	SSL_CTX_free(ssl_server_ctx);
	return 0;

}
#endif
