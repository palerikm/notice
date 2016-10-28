

#include <string.h>

#include "register.h"


int
deregisterUser(int                  socket,
               struct registration* registrations,
               size_t*              numReg)
{
  printf("De-Register user on socket: %i (NumReg:%lu)\n", socket, *numReg);
  for (size_t i = 0; i < *numReg; i++)
  {
    if (registrations[i].socketfd == socket)
    {
      memset( &registrations[i], 0, sizeof(struct registration) );

      /* Move rest of the registrations down one..... */

      for (size_t j = i + 1; j < *numReg; j++)
      {
        memcpy( &registrations[i], &registrations[j],
                sizeof(struct registration) );
      }
      (*numReg)--;
      return 1;
    }
  }
  return -1;
}

int
registerUser(char*                user,
             int                  socket,
             struct registration* registrations,
             size_t*              numReg)
{
  struct registration* reg;
  reg = findUserByName(user,registrations, *numReg);

  if (reg != NULL)
  {
    return 403;
  }

  if (*numReg < MAX_REG)
  {
    registrations[*numReg].socketfd = socket;
    strncpy(registrations[*numReg].user,
            user, MAX_USERNAME_LEN);
    (*numReg)++;
    printf("Registered user (%s) on socket %i\n", user, socket);
    return 200;
  }
  return 403;
}

struct registration*
findUserBySocket(int                  socketfd,
                 struct registration* registrations,
                 int                  numReg)
{
  int i;
  for (i = 0; i < numReg; i++)
  {
    if (registrations[i].socketfd == socketfd)
    {
      return &registrations[i];
    }
  }
  return NULL;
}

struct registration*
findUserByName(char*                name,
               struct registration* registrations,
               int                  numReg)
{
  int i;
  for (i = 0; i < numReg; i++)
  {
    if (strncmp(name, registrations[i].user, 128) == 0)
    {
      return &registrations[i];
    }
  }
  return NULL;
}
