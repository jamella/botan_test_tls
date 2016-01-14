#include <botan/credentials_manager.h>
#include <botan/pkcs8.h>
#include <botan/data_src.h>
#include <botan/pk_keys.h>

class TLS_Credentials_Manager : public Botan::Credentials_Manager
{
  public:
    TLS_Credentials_Manager(Botan::RandomNumberGenerator& rng,
                            const std::string& crt,
                            const std::string& key,
                            const std::string& ca);

    std::vector<Botan::Certificate_Store*>
    trusted_certificate_authorities(const std::string& type,
                                    const std::string& hostname) override;

    void verify_certificate_chain(const std::string& type,
                                  const std::string& purported_hostname,
                                  const std::vector<Botan::X509_Certificate>& cert_chain) override;

    std::vector<Botan::X509_Certificate> cert_chain(const std::vector<std::string>& algs,
                                                    const std::string& type,
                                                    const std::string& hostname) override;

    Botan::Private_Key *private_key_for(const Botan::X509_Certificate& cert,
                                        const std::string& type,
                                        const std::string& context) override;

  private:
    struct Certificate_Info
    {
      std::vector<Botan::X509_Certificate> certs;
      std::shared_ptr<Botan::Private_Key> key;
    };

    std::vector<Certificate_Info> m_creds;
    std::vector<std::shared_ptr<Botan::Certificate_Store>> m_certstores;
};
