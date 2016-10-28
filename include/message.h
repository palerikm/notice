#pragma once



#include <stdbool.h>


#include "register.h"

enum msg_type {
  NONE,
  REGISTER,
  INVITE,
  OK,
  ACK,
  FRAG,
};


int
sendall(int         s,
        const char* buf,
        int*        len);
int
handleMsg(int                  socketfd,
          char*                msg,
          size_t               msglen,
          struct registration* registrations,
          size_t*              numReg);

int
storeMsg(int                  socketfd,
         const char*          msg,
         int                  msg_len,
         struct registration* registrations,
         size_t               numReg);


int
handle200OkMsg(int                  socketfd,
               const char*          msg,
               int                  msg_len,
               struct registration* registrations,
               size_t               numReg);

int
handleRegisterMsg(int                  socketfd,
                  const char*          msg,
                  size_t               msglen,
                  struct registration* registrations,
                  size_t*              numReg);

int
getMsgType(const char* msg);


int
handleInviteMsg(int                  socketfd,
                const char*          msg,
                size_t               msglen,
                struct registration* registrations,
                size_t               numReg);


bool
completeMessage(const char* msg,
                size_t      len);
