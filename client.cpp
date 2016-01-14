#include <iostream>
#include <string>

#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include <botan/tls_client.h>
#include <botan/auto_rng.h>
#include <botan/tls_policy.h>
#include <botan/bigint.h>
#include <botan/hex.h>
#include <botan/tls_version.h>

#include "credentials.h"


int socket_fd = 0;

void write_fn(const unsigned char data[], size_t length)
{
  size_t offset = 0;

  while (length > 0)
  {
    ssize_t sent = write(socket_fd, (const char *) data + offset, length);
    if (sent == -1)
    {
      std::cout << "Socket write failed!" << std::endl;
    }

    offset += sent;
    length -= sent;
  }
}

void process_data(const unsigned char data[], size_t length)
{
  size_t i;

  for (i = 0; i < length; i += 1)
  {
    std::cout << data[i];
  }
}

void alert_received(Botan::TLS::Alert alert, const unsigned char data[], size_t length)
{
  std::cout << "Alert: " << alert.type_string() << std::endl;
}

bool handshake_complete(const Botan::TLS::Session& session)
{
  std::cout << "Handshake complete, " << session.version().to_string()
            << " using " << session.ciphersuite().to_string() << std::endl;

  if (!session.session_id().empty())
  {
    std::cout << "Session ID " << Botan::hex_encode(session.session_id()) << std::endl;
  }

  if (!session.session_ticket().empty())
  {
    std::cout << "Session ticket " << Botan::hex_encode(session.session_ticket()) << std::endl;
  }

  return true;
}


int main(int argc, char *argv[])
{
  if (argc != 6)
  {
    std::cout << "Usage: " << argv[0] << " host port crt ca key" << std::endl;
    return -1;
  }

  std::string host = argv[1];
  std::string port = argv[2];
  std::string crt = argv[3];
  std::string ca = argv[4];
  std::string key = argv[5]; // Why needed?

  Botan::AutoSeeded_RNG rng;
  Botan::TLS::Strict_Policy policy;
  Botan::TLS::Session_Manager_In_Memory session_manager(rng);
  TLS_Credentials_Manager creds(rng, crt, key, ca);

  hostent* host_addr = gethostbyname(host.c_str());
  if (host_addr == NULL)
  {
    std::cout << "gethostbyname failed." << std::endl;
    return -1;
  }

  if (host_addr->h_addrtype != AF_INET)
  {
    std::cout << "addrtype not supported." << std::endl;
    return -1;
  }

  socket_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0)
  {
    std::cout << "socket failed," << std::endl;
    return -1;
  }

  sockaddr_in socket_info = {};
  socket_info.sin_family = AF_INET;
  socket_info.sin_port = htons(Botan::to_u32bit(port));
  memcpy(&socket_info.sin_addr, host_addr->h_addr, host_addr->h_length);

  if (connect(socket_fd, (sockaddr*) &socket_info, sizeof(struct sockaddr)) != 0)
  {
    close(socket_fd);
    std::cout << "connect failed." << std::endl;
    return -1;
  }

  Botan::TLS::Client client(write_fn,
                            process_data,
                            alert_received,
                            handshake_complete,
                            session_manager,
                            creds,
                            policy,
                            rng,
                            Botan::TLS::Server_Information(host, port),
                            Botan::TLS::Protocol_Version(Botan::TLS::Protocol_Version::TLS_V12),
                            {});

  while (!client.is_closed())
  {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(socket_fd, &readfds);

    if (client.is_active())
    {
      FD_SET(STDIN_FILENO, &readfds);
    }

    struct timeval timeout = { 1, 0 };

    select(socket_fd + 1, &readfds, nullptr, nullptr, &timeout);

    if (FD_ISSET(socket_fd, &readfds))
    {
      unsigned char buf[4 * 1024] = {};
      ssize_t got = read(socket_fd, buf, sizeof(buf));

      if (got == 0)
      {
        std::cout << "EOF on socket." << std::endl;
        break;
      }
      else if (got == -1)
      {
        std::cout << "Error on socket." << std::endl;
        break;
      }
  
      client.received_data(buf, got);
    }

    if (FD_ISSET(STDIN_FILENO, &readfds))
    {
      unsigned char buf[1024] = {};
      ssize_t got = read(STDIN_FILENO, buf, sizeof(buf));

      if (got == 0)
      {
        std::cout << "EOF on stdin." << std::endl;
        break;
      }
      else if (got == -1)
      {
        std::cout << "Error on stdin" << std::endl;
        break;
      }

      if ((got == 2) && (buf[1] == '\n'))
      {
        switch (buf[0])
        {
          case 'H':
          case 'h':
            client.heartbeat(&buf[0], 1);
            client.send(buf, got);
            break;
          case 'Q':
          case 'q':
            client.close();
            break;
          case 'R':
          case 'r':
            client.renegotiate(buf[0] == 'R');
            break;
          default:
            client.send(buf, got);
            break;
        }
      }
      else
      {
        client.send(buf, got);
      }

      if (client.timeout_check())
      {
        std::cout << "Timeout detected." << std::endl;
      }
    }
  }

  close(socket_fd);

  return 0;
}
