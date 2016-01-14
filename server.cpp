#include <sys/socket.h>
#include <netdb.h>
#include <iostream>
#include <unistd.h>

#include <botan/bigint.h>
#include <botan/auto_rng.h>
#include <botan/tls_server.h>
#include <botan/hex.h>

#include "credentials.h"

int conn_fd = 0;

void write_fn(const unsigned char buf[], size_t length)
{
  while (length > 0)
  {
    ssize_t sent = send(conn_fd, buf, length, MSG_NOSIGNAL);
    if (sent < 0)
    {
      std::cout << "send failed" << std::endl;
    }

    buf += sent;
    length -= sent;
  }
}

void process_data(const unsigned char data[], size_t length)
{
  // Just print whatever received
  std::string s;
  for (size_t i = 0; i < length; i += 1)
  {
    s += static_cast<unsigned char>(data[i]);
  }

  std::cout << s << std::endl;
}

void received_alert(Botan::TLS::Alert alert, const unsigned char data[], size_t length)
{
  std::cout << "Alert: " << alert.type_string() << std::endl;
}

bool handshake_complete(const Botan::TLS::Session& session)
{
  std::cout << "Handshake complete, " << session.version().to_string()
            << "using " << session.ciphersuite().to_string() << std::endl;

  if (!session.session_id().empty())
  {
    std::cout << "Session ID " << Botan::hex_encode(session.session_id()) << std::endl;
  }

  if (!session.session_ticket().empty())
  {
    std::cout << "Session ticket: " << Botan::hex_encode(session.session_ticket()) << std::endl;
  }

  return true;
}

int main(int argc, char **argv)
{
  if (argc != 5)
  {
    std::cout << "Usage: " << argv[0] << " ca crt key port" << std::endl;
    return 1;
  }

  const std::string server_ca = argv[1];
  const std::string server_crt = argv[2];
  const std::string server_key = argv[3];
  const std::string server_port = argv[4];

  Botan::AutoSeeded_RNG rng;
  Botan::TLS::Strict_Policy policy;
  Botan::TLS::Session_Manager_In_Memory session_manager(rng);
  TLS_Credentials_Manager creds(rng, server_crt, server_key, server_ca);

  int socketfd;
  struct addrinfo host_info = {};
  struct addrinfo *host_info_list = NULL;

  host_info.ai_family = AF_INET;
  host_info.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(nullptr, server_port.c_str(), &host_info, &host_info_list) != 0)
  {
    std::cout << "getaddrinfo failed" << std::endl;
    return -1;
  }

  socketfd = socket(host_info_list->ai_family, host_info_list->ai_socktype, host_info_list->ai_protocol);
  if (socketfd < 0)
  {
    std::cout << "socket failed" << std::endl;
    return -1;
  }
  
  int yes = 1;
  if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
  {
    std::cout << "setsockopt failed" << std::endl;
    return -1;
  }

  if (bind(socketfd, host_info_list->ai_addr, host_info_list->ai_addrlen) < 0)
  {
    std::cout << "bind failed" << std::endl;
    return -1;
  }

  if (listen(socketfd, 5) < 0)
  {
    std::cout << "listen failed" << std::endl;
    return -1;
  }

  while (true)
  {
    conn_fd = accept(socketfd, nullptr, nullptr);
    if (conn_fd > 0)
    {
      
      Botan::TLS::Server TLS_Server(write_fn,
                                    process_data,
                                    received_alert,
                                    handshake_complete,
                                    session_manager,
                                    creds,
                                    policy,
                                    rng);

      while (!TLS_Server.is_closed())
      {
        unsigned char buf[4 * 1024] = { 0 };
        ssize_t data_read = read(conn_fd, buf, sizeof(buf));
        if (data_read < 0)
        {
          std::cout << "read failed" << std::endl;
          break;
        }
        else if (data_read == 0)
        {
          std::cout << "EOF on socket" << std::endl;
          break;
        }

        TLS_Server.received_data(buf, data_read);
      }

      close(conn_fd);
    }
    else
    {
      std::cout << "accept failed" << std::endl;
      return -1;
    }
  }
  
  return 0;
}
