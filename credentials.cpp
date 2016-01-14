#include <iostream>

#include "credentials.h"

TLS_Credentials_Manager::TLS_Credentials_Manager(Botan::RandomNumberGenerator& rng,
                                                 const std::string& crt,
                                                 const std::string& key,
                                                 const std::string& ca)
{
  /* Load certificate. */
  Certificate_Info cert;
  cert.key.reset(Botan::PKCS8::load_key(key, rng));
  try
  {
    cert.certs.push_back(Botan::X509_Certificate(crt));
  }
  catch (std::exception& e)
  {
    std::cout << "Error while loading certificates." << std::endl;
    throw;
  }

  m_creds.push_back(cert);

  /* Load ca. */
  std::shared_ptr<Botan::Certificate_Store_In_Memory> cs(new Botan::Certificate_Store_In_Memory());
  try
  {
    cs->add_certificate(Botan::X509_Certificate(ca));
  }
  catch (std::exception& e)
  {
    std::cout << "Error while loading ca." << std::endl;
    throw;
  }

  m_certstores.push_back(cs);
}

std::vector<Botan::Certificate_Store*>
TLS_Credentials_Manager::trusted_certificate_authorities(const std::string& type,
                                                         const std::string& hostname)
{
  std::vector<Botan::Certificate_Store*> v;

  for (auto&& cs : m_certstores)
  {
    v.push_back(cs.get());
  }

  return v;
}

void TLS_Credentials_Manager::verify_certificate_chain(const std::string& type,
                                                       const std::string& purported_hostname,
                                                       const std::vector<Botan::X509_Certificate>& cert_chain)
{
  try
  {
    Credentials_Manager::verify_certificate_chain(type, purported_hostname, cert_chain);
  }
  catch (std::exception& e)
  {
    /* Client and server certificates do not match. */
    std::cout << e.what() << std::endl;
    throw;
  }
}


std::vector<Botan::X509_Certificate> TLS_Credentials_Manager::cert_chain(const std::vector<std::string>& algs,
                                                                  const std::string& type,
                                                                  const std::string& hostname)
{
  if (hostname != "")
  {
    for (auto&& c : m_creds)
    {
      if (std::find(algs.begin(), algs.end(), c.key->algo_name()) == algs.end())
      {
        continue;
      }

      if (!c.certs[0].matches_dns_name(hostname))
      {
        continue;
      }

      return c.certs;
    }
  }

  return std::vector<Botan::X509_Certificate>();
}

Botan::Private_Key* TLS_Credentials_Manager::private_key_for(const Botan::X509_Certificate& cert,
                                                             const std::string& type,
                                                             const std::string& hostname)
{
  for (auto&& c : m_creds)
  {
    if (cert == c.certs[0])
    {
      return c.key.get();
    }
  }

  return nullptr;
}
