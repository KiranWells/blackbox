#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>

int main(int argc, char** argv) {
  // file testing
  printf("File testing ...\n");
  int file_1 = open("/tmp/blackbox-test-1", O_WRONLY | O_TRUNC | O_CREAT, 0644);
  int file_2 = openat(AT_FDCWD, "/tmp/blackbox-test-1", O_RDWR | O_TRUNC | O_CREAT, 0644);

  const char *data = "This is some data written to a file\0\xFF";
  const size_t DATA_SIZE = 37;
  write(file_1, data, DATA_SIZE);
  char *read_data = (char*)malloc(512);
  close(file_1);
  file_1 = open("/tmp/blackbox-test-1", O_RDONLY, 0644);
  read(file_1, read_data, DATA_SIZE);
  close(file_1);
  close(file_2);

  // connection testing
  printf("Connection testing ...\n");
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  int status;
  struct addrinfo *addr_list;
  if ((status = getaddrinfo(NULL, "8080", &hints, &addr_list)) != 0) {
     fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
     exit(EXIT_FAILURE);
  }
  
  int sfd;
  struct addrinfo *addr_ptr;
  for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
    sfd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
    if (sfd == -1)
      continue;

    if (bind(sfd, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == 0)
      break;

    close(sfd);
  }

  freeaddrinfo(addr_list);

  if (addr_ptr == NULL) {               /* No address succeeded */
   fprintf(stderr, "Could not bind\n");
   exit(EXIT_FAILURE);
  }
  // socket data is not tracked, so we immediately close
  close(sfd);

  // process testing
  printf("Process testing ...\n");
  if (fork() != 0) {
    // child
    execve("/bin/ls", NULL, NULL);
  }

  wait(NULL);
  return 0;
}
