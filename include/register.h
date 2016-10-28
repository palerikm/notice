#pragma once

#include <stdio.h>

#define MAX_USERNAME_LEN 40
#define MAX_BUF 8192
#define MAX_REG 100


struct registration {
  int    socketfd;
  int    lastFrom;
  char   buf[MAX_BUF];
  size_t buflen;
  char   user[MAX_USERNAME_LEN];
};


struct registration*
findUserByName(char*                name,
               struct registration* registrations,
               int                  numReg);

struct registration*
findUserBySocket(int                  socketfd,
                 struct registration* registrations,
                 int                  numReg);

int
registerUser(char*                user,
             int                  socket,
             struct registration* registrations,
             size_t*              numReg);

int
deregisterUser(int                  socket,
               struct registration* registrations,
               size_t*              numReg);
