


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/socket.h>

#include "message.h"

int
sendall(int         s,
        const char* buf,
        int*        len)
{
  int total     = 0;      /* how many bytes we've sent */
  int bytesleft = *len;   /* how many we have left to send */
  int n;

  while (total < *len)
  {
    n = send(s, buf + total, bytesleft, 0);
    if (n == -1)
    {
      break;
    }
    total     += n;
    bytesleft -= n;
  }

  *len = total;   /* return number actually sent here */

  return n == -1 ? -1 : 0; /* return -1 on failure, 0 on success */
}


int
handleMsg(int                  socketfd,
          char*                imsg,
          size_t               imsglen,
          struct registration* registrations,
          size_t*              numReg)
{
  char*   msg;
  size_t* msglen;
  printf("Handling message\n");
  int idx = storeMsg(socketfd, imsg, imsglen, registrations, *numReg);
  if (idx != -1)
  {
    msg    = registrations[idx].buf;
    msglen = &registrations[idx].buflen;
  }
  else
  {
    msg    = imsg;
    msglen = &imsglen;
  }
  switch ( getMsgType(msg) )
  {
  case REGISTER:
    handleRegisterMsg(socketfd, msg, *msglen, registrations, numReg);
    break;
  case INVITE:
    if (handleInviteMsg(socketfd, msg, *msglen, registrations, *numReg) == 1)
    {
      printf("     ######## Resetting buffer  (invite) ######\n");
      memset(msg, 0, *msglen);
      *msglen = 0;
    }
    break;
  case OK:
    if ( handle200OkMsg(socketfd, msg, *msglen, registrations, *numReg) )
    {
      printf("     ######## Resetting buffer  (200Ok) ######\n");
      memset(msg, 0, *msglen);
      *msglen = 0;
    }
    break;
  case ACK:
    printf("Got ack, should handle..\n");
    break;
  case FRAG:
    printf("Handling Fragment (Should not happen...)\n");
    break;
  }

  return 0;
}

int
storeMsg(int                  socketfd,
         const char*          msg,
         int                  msg_len,
         struct registration* registrations,
         size_t               numReg)
{
  size_t i;
  for (i = 0; i < numReg; i++)
  {
    if (socketfd == registrations[i].socketfd)
    {
      if (registrations[i].buflen + msg_len > MAX_BUF)
      {
        registrations[i].buflen = 0;
        memset( registrations[i].buf, 0, sizeof(registrations[i].buf) );
        return -1;
      }
      memcpy(registrations[i].buf + registrations[i].buflen, msg, msg_len);
      registrations[i].buflen += msg_len;
      printf(" ##### MSG stored, cur len: %lu ######\n",
             registrations[i].buflen);
      return i;
    }
  }
  return -1;
}


int
handle200OkMsg(int                  socketfd,
               const char*          msg,
               int                  msg_len,
               struct registration* registrations,
               size_t               numReg)
{
  char  str[MAX_BUF];
  char  str_to[MAX_USERNAME_LEN];
  char* delim = "\n:\\\r";
  char* tok;

  printf("Handling 200OK\n");
  if ( !completeMessage(msg, msg_len) )
  {
    printf("Message not complete... waiting for next bit..\n");
    return 0;
  }

  strncpy(str, msg, 4096);
  tok = strtok( (char*)str, delim );

  /* Pesky parsing again */
  /* Find the to tags */
  while (tok != NULL)
  {

    if (strncmp(tok, "To", 2) == 0)
    {
      tok = strtok(NULL, delim);
      while ( isspace(*tok) )
      {
        tok++;
      }

      strncpy( str_to, tok, strlen(tok) );
      struct registration* from = findUserByName(str_to, registrations, numReg);
      struct registration* to   = findUserBySocket(socketfd,
                                                   registrations,
                                                   numReg);

      if ( (from == NULL) || (to == NULL) )
      {
        printf("Unable to find from or to..\n");
        return 0;
      }
      if (sendall(from->socketfd, msg, &msg_len) == -1)
      {
        perror("200 OK send");
        printf("We only sent %d bytes because of the error!\n", msg_len);
      }
      return 100;
    }
    tok = strtok(NULL, delim);
  }
  return 1;
}




int
inviteUser(char*                user,
           int                  lastFrom,
           const char*          msg,
           int                  msg_len,
           struct registration* registrations,
           size_t               numReg)
{
  struct registration* reg;
  reg = findUserByName(user, registrations, numReg);
  if (reg != NULL)
  {
    printf("User found! on socket: %i\n", reg->socketfd);
    reg->lastFrom = lastFrom;
    if (sendall(reg->socketfd, msg, &msg_len) == -1)
    {
      perror("sendall");
      printf("We only sent %d bytes because of the error!\n", msg_len);
    }
    return 100;
  }
  else
  {
    printf("No user found (%s)\n", user);
    return 404;
  }
}


int
handleRegisterMsg(int                  socketfd,
                  const char*          msg,
                  size_t               msglen,
                  struct registration* registrations,
                  size_t*              numReg)
{
  int ret;
  int  userNameLen = msglen - 9 - 1;
  char user[MAX_USERNAME_LEN];
  if (userNameLen < MAX_USERNAME_LEN)
  {
    memset(user, 0, MAX_USERNAME_LEN);
    strncpy(user, msg + 9, userNameLen);
    strcat(user, "\0");
    ret = registerUser(user, socketfd, registrations, numReg);
  }
  else
  {
    ret = 401;
  }
  if (ret == 200)
  {
    char retStr[] = "200 OK\r\n\0";
    int  len      = strlen(retStr);
    if (sendall(socketfd, retStr, &len) == -1)
    {
      perror("200 OK send (Register)");
    }
  }
  else
  {
    char retStr[] = "401\r\n\0";
    int  len      = strlen(retStr);
    if (sendall(socketfd, retStr, &len) == -1)
    {
      perror("401 send (Register)");
    }
  }
  return 1;
}

int
getMsgType(const char* msg)
{
  if (strncmp(msg, "REGISTER", 8) == 0)
  {
    return REGISTER;
  }
  else if (strncmp(msg, "INVITE", 6) == 0)
  {
    return INVITE;
  }
  else if (strncmp(msg, "200 OK", 6) == 0)
  {
    return OK;
  }
  else if (strncmp(msg, "ACK", 3) == 0)
  {
    return ACK;
  }
  else
  {
    return FRAG;
  }
}

int
handleInviteMsg(int                  socketfd,
                const char*          msg,
                size_t               msglen,
                struct registration* registrations,
                size_t               numReg)
{
  int        ret;
  char       str[MAX_BUF];
  char       user[128];
  const char delim[2] = "\n";
  printf("Handling Invite \n");

  if ( !completeMessage(msg, msglen) )
  {
    printf("Message not complet... waiting for next bit..\n");
    return 0;
  }

  /* Get the user part..strtok() messes op the original string.. */
  strncpy(str,  msg,                    MAX_BUF);
  strncpy(user, strtok(str + 7, delim), 128);

  ret = inviteUser(user, socketfd,
                   msg, msglen,
                   registrations, numReg);
  if (ret == 100)
  {
    char retStr[] = "100 Trying\r\n\0";
    int  len      = strlen(retStr);
    if (sendall(socketfd, retStr, &len) == -1)
    {
      perror("100 Trying send");
    }
  }
  else
  {
    char retStr[] = "404\r\n\0";
    int  len      = strlen(retStr);
    if (sendall(socketfd, retStr, &len) == -1)
    {
      perror("404 send");
    }
  }
  return 1;
}

bool
completeMessage(const char* msg,
                size_t      len)
{
  /* Is there A content length after /r/n? */
  /* If so can we hold the entire message or do we need to wait? */
  (void)len;
  char* data = NULL;
  data = strstr(msg, "\r\n");
  if (data != NULL)
  {
    char* content = NULL;
    content = strstr(msg, "Content-Length:");
    if (content != NULL)
    {
      int value = atoi(content + 15);
      int real  = strlen(data + 2);
      printf("Content-Length: %i  (%i)\n", value, real);
      if (real < value)
      {
        return false;
      }
      return true;
    }
    return true;
  }
  return true;
}
