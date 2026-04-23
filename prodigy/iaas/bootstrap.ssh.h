#pragma once

#include <services/filesystem.h>
#include <services/vault.h>

static inline auto prodigyDefaultBootstrapSSHPrivateKeyPath(void)
{
   return "/var/lib/prodigy/ssh/bootstrap_ed25519"_ctv;
}

static inline auto prodigyDefaultBootstrapSSHPublicKeyPath(void)
{
   return "/var/lib/prodigy/ssh/bootstrap_ed25519.pub"_ctv;
}

static inline auto prodigyDefaultBootstrapSSHDirectory(void)
{
   return "/var/lib/prodigy/ssh"_ctv;
}

static inline auto prodigyDefaultBootstrapSSHHostPrivateKeyPath(void)
{
   return "/etc/ssh/ssh_host_ed25519_key"_ctv;
}

static inline auto prodigyDefaultBootstrapSSHHostPublicKeyPath(void)
{
   return "/etc/ssh/ssh_host_ed25519_key.pub"_ctv;
}

static inline bool prodigyBootstrapSSHKeyPackageConfigured(const Vault::SSHKeyPackage& package)
{
   return package.privateKeyOpenSSH.size() > 0 || package.publicKeyOpenSSH.size() > 0;
}

static inline bool prodigyReadSSHKeyPackageFromPrivateKeyPath(const String& privateKeyPath, Vault::SSHKeyPackage& package, String *failure = nullptr)
{
   package.clear();
   if (failure) failure->clear();

   if (privateKeyPath.size() == 0)
   {
      if (failure) failure->assign("bootstrap ssh private key path required"_ctv);
      return false;
   }

   Filesystem::openReadAtClose(-1, privateKeyPath, package.privateKeyOpenSSH);
   if (package.privateKeyOpenSSH.size() == 0)
   {
      if (failure) failure->snprintf<"failed to read bootstrap ssh private key '{}'"_ctv>(privateKeyPath);
      return false;
   }

   String publicKeyPath = {};
   publicKeyPath.snprintf<"{}.pub"_ctv>(privateKeyPath);
   Filesystem::openReadAtClose(-1, publicKeyPath, package.publicKeyOpenSSH);
   if (package.publicKeyOpenSSH.size() == 0)
   {
      if (failure) failure->snprintf<"failed to read bootstrap ssh public key '{}'"_ctv>(publicKeyPath);
      package.clear();
      return false;
   }

   if (Vault::validateSSHKeyPackageEd25519(package, failure) == false)
   {
      package.clear();
      return false;
   }

   if (failure) failure->clear();
   return true;
}

static inline bool prodigyResolveBootstrapSSHKeyPackage(
   const Vault::SSHKeyPackage& configuredPackage,
   const String& privateKeyPath,
   const String& generatedComment,
   bool generateIfMissing,
   Vault::SSHKeyPackage& package,
   String *failure = nullptr)
{
   package.clear();
   if (failure) failure->clear();

   if (prodigyBootstrapSSHKeyPackageConfigured(configuredPackage))
   {
      package = configuredPackage;
      if (Vault::validateSSHKeyPackageEd25519(package, failure) == false)
      {
         package.clear();
         return false;
      }

      return true;
   }

   if (privateKeyPath.size() > 0)
   {
      return prodigyReadSSHKeyPackageFromPrivateKeyPath(privateKeyPath, package, failure);
   }

   if (generateIfMissing == false)
   {
      return true;
   }

   if (Vault::generateSSHKeyPackageEd25519(package, generatedComment, failure) == false)
   {
      package.clear();
      return false;
   }

   return true;
}

static inline bool prodigyReadBootstrapSSHPublicKey(const String& privateKeyPath, String& publicKey, String *failure = nullptr)
{
   publicKey.clear();
   if (failure) failure->clear();

   if (privateKeyPath.size() == 0)
   {
      if (failure) failure->assign("bootstrap ssh private key path required"_ctv);
      return false;
   }

   String publicKeyPath = {};
   publicKeyPath.snprintf<"{}.pub"_ctv>(privateKeyPath);
   Filesystem::openReadAtClose(-1, publicKeyPath, publicKey);
   if (publicKey.size() == 0)
   {
      if (failure) failure->snprintf<"failed to read bootstrap ssh public key '{}'"_ctv>(publicKeyPath);
      return false;
   }

   while (publicKey.size() > 0)
   {
      uint8_t tail = publicKey[publicKey.size() - 1];
      if (tail != '\n' && tail != '\r' && tail != '\t' && tail != ' ')
      {
         break;
      }

      publicKey.trim(1);
   }

   if (publicKey.size() == 0)
   {
      if (failure) failure->snprintf<"bootstrap ssh public key '{}' is empty"_ctv>(publicKeyPath);
      return false;
   }

   return true;
}

static inline void prodigyAppendSingleQuotedShellLiteral(String& output, const String& value)
{
   output.append('\'' );

   for (uint64_t index = 0; index < value.size(); ++index)
   {
      if (value[index] == '\'')
      {
         output.append("'\"'\"'"_ctv);
      }
      else
      {
         output.append(value[index]);
      }
   }

   output.append('\'');
}

static inline void prodigyResolveBootstrapSSHUser(const String& configuredUser, String& resolvedUser)
{
   if (configuredUser.size() > 0)
   {
      resolvedUser.assign(configuredUser);
   }
   else
   {
      resolvedUser.assign("root"_ctv);
   }
}

static inline void prodigyBuildBootstrapSSHUserData(const String& configuredUser, const String& publicKey, const Vault::SSHKeyPackage& hostKeyPackage, String& script)
{
   script.clear();
   String sshUser = {};
   prodigyResolveBootstrapSSHUser(configuredUser, sshUser);
   bool configureHostKey = prodigyBootstrapSSHKeyPackageConfigured(hostKeyPackage);

   script.append("#!/bin/sh\nset -eu\n"_ctv);
   script.append("BOOTSTRAP_USER="_ctv);
   prodigyAppendSingleQuotedShellLiteral(script, sshUser);
   script.append("\nBOOTSTRAP_KEY="_ctv);
   prodigyAppendSingleQuotedShellLiteral(script, publicKey);
   script.append("\n"_ctv);
   if (configureHostKey)
   {
      script.append("BOOTSTRAP_HOST_PRIVATE_KEY="_ctv);
      prodigyAppendSingleQuotedShellLiteral(script, hostKeyPackage.privateKeyOpenSSH);
      script.append("\nBOOTSTRAP_HOST_PUBLIC_KEY="_ctv);
      prodigyAppendSingleQuotedShellLiteral(script, hostKeyPackage.publicKeyOpenSSH);
      script.append("\n"_ctv);
   }
   script.append(
      "resolve_home_dir() {\n"
      "  user=\"$1\"\n"
      "  if [ \"$user\" = root ]; then\n"
      "    printf '%s\\n' /root\n"
      "    return 0\n"
      "  fi\n"
      "  home_dir=''\n"
      "  if command -v getent >/dev/null 2>&1; then\n"
      "    home_dir=$(getent passwd \"$user\" | cut -d: -f6)\n"
      "  else\n"
      "    home_dir=$(awk -F: -v user=\"$user\" '$1 == user { print $6 }' /etc/passwd | head -n 1)\n"
      "  fi\n"
      "  if [ -n \"$home_dir\" ]; then\n"
      "    printf '%s\\n' \"$home_dir\"\n"
      "  else\n"
      "    printf '%s\\n' \"/home/$user\"\n"
      "  fi\n"
      "}\n"
      "ensure_user() {\n"
      "  user=\"$1\"\n"
      "  if id -u \"$user\" >/dev/null 2>&1; then\n"
      "    return 0\n"
      "  fi\n"
      "  if command -v useradd >/dev/null 2>&1; then\n"
      "    useradd -m -s /bin/sh \"$user\" >/dev/null 2>&1 || useradd -m \"$user\" >/dev/null 2>&1 || true\n"
      "  fi\n"
      "  if ! id -u \"$user\" >/dev/null 2>&1 && command -v adduser >/dev/null 2>&1; then\n"
      "    adduser --disabled-password --gecos '' \"$user\" >/dev/null 2>&1 || adduser -D \"$user\" >/dev/null 2>&1 || true\n"
      "  fi\n"
      "  id -u \"$user\" >/dev/null 2>&1\n"
      "}\n"
      "install_key() {\n"
      "  user=\"$1\"\n"
      "  home_dir=\"$2\"\n"
      "  ssh_dir=\"$home_dir/.ssh\"\n"
      "  mkdir -p \"$ssh_dir\"\n"
      "  chmod 700 \"$ssh_dir\"\n"
      "  touch \"$ssh_dir/authorized_keys\"\n"
      "  grep -qxF \"$BOOTSTRAP_KEY\" \"$ssh_dir/authorized_keys\" || printf '%s\\n' \"$BOOTSTRAP_KEY\" >> \"$ssh_dir/authorized_keys\"\n"
      "  chmod 600 \"$ssh_dir/authorized_keys\"\n"
      "  if [ \"$user\" = root ]; then\n"
      "    chown -R 0:0 \"$ssh_dir\" 2>/dev/null || true\n"
      "  else\n"
      "    chown -R \"$user\":\"$user\" \"$ssh_dir\" 2>/dev/null || true\n"
      "  fi\n"
      "}\n"
      "install_host_key() {\n"
      "  if [ -z \"${BOOTSTRAP_HOST_PRIVATE_KEY:-}\" ] || [ -z \"${BOOTSTRAP_HOST_PUBLIC_KEY:-}\" ]; then\n"
      "    return 0\n"
      "  fi\n"
      "  umask 077\n"
      "  mkdir -p /etc/ssh\n"
      "  printf '%s\\n' \"$BOOTSTRAP_HOST_PRIVATE_KEY\" > /etc/ssh/ssh_host_ed25519_key\n"
      "  printf '%s\\n' \"$BOOTSTRAP_HOST_PUBLIC_KEY\" > /etc/ssh/ssh_host_ed25519_key.pub\n"
      "  chown 0:0 /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || true\n"
      "  chmod 600 /etc/ssh/ssh_host_ed25519_key\n"
      "  chmod 644 /etc/ssh/ssh_host_ed25519_key.pub\n"
      "}\n"
      "if [ \"$BOOTSTRAP_USER\" != root ]; then\n"
      "  ensure_user \"$BOOTSTRAP_USER\"\n"
      "fi\n"
      "BOOTSTRAP_HOME=$(resolve_home_dir \"$BOOTSTRAP_USER\")\n"
      "mkdir -p \"$BOOTSTRAP_HOME\"\n"
      "install_key \"$BOOTSTRAP_USER\" \"$BOOTSTRAP_HOME\"\n"
      "install_host_key\n"_ctv);
   script.append("if [ \"$BOOTSTRAP_USER\" = root ]; then\n"_ctv);
   script.append(
      "  if command -v usermod >/dev/null 2>&1; then\n"
      "    usermod -s /bin/sh root >/dev/null 2>&1 || true\n"
      "  fi\n"
      "  if [ -f /etc/ssh/sshd_config ]; then\n"
      "    sed -i 's/^#\\?PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config || true\n"
      "    if ! grep -q '^PermitRootLogin prohibit-password$' /etc/ssh/sshd_config; then printf '%s\\n' 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config; fi\n"
      "    sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config || true\n"
      "    if ! grep -q '^PasswordAuthentication no$' /etc/ssh/sshd_config; then printf '%s\\n' 'PasswordAuthentication no' >> /etc/ssh/sshd_config; fi\n"
      "    sed -i 's/^#\\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config || true\n"
      "    if ! grep -q '^PubkeyAuthentication yes$' /etc/ssh/sshd_config; then printf '%s\\n' 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config; fi\n"
      "  fi\n"
      "fi\n"_ctv);
   script.append("(systemctl restart sshd || systemctl restart ssh || service ssh restart || service sshd restart || true)\n"_ctv);
}

static inline void prodigyBuildBootstrapSSHCloudConfig(const String& configuredUser, const String& publicKey, const Vault::SSHKeyPackage& hostKeyPackage, String& config)
{
   config.clear();

   String sshUser = {};
   prodigyResolveBootstrapSSHUser(configuredUser, sshUser);
   bool rootUser = (sshUser == "root"_ctv);
   bool configureHostKey = prodigyBootstrapSSHKeyPackageConfigured(hostKeyPackage);

   config.append("#cloud-config\n"_ctv);
   config.append("ssh_pwauth: false\n"_ctv);
   if (rootUser)
   {
      config.append("disable_root: false\n"_ctv);
   }

   config.append("users:\n"_ctv);
   config.append("  - default\n"_ctv);
   config.append("  - name: "_ctv);
   config.append(sshUser);
   config.append("\n"_ctv);
   if (rootUser == false)
   {
      config.append("    shell: /bin/bash\n"_ctv);
   }
   config.append("    lock_passwd: true\n"_ctv);
   config.append("    ssh_authorized_keys:\n"_ctv);
   config.append("      - "_ctv);
   config.append(publicKey);
   config.append("\n"_ctv);

   config.append("write_files:\n"_ctv);
   config.append("  - path: /etc/ssh/sshd_config.d/99-prodigy-bootstrap.conf\n"_ctv);
   config.append("    owner: root:root\n"_ctv);
   config.append("    permissions: '0644'\n"_ctv);
   config.append("    content: |\n"_ctv);
   if (rootUser)
   {
      config.append("      PermitRootLogin prohibit-password\n"_ctv);
   }
   config.append("      PasswordAuthentication no\n"_ctv);
   config.append("      PubkeyAuthentication yes\n"_ctv);
   if (configureHostKey)
   {
      config.append("  - path: /etc/ssh/ssh_host_ed25519_key\n"_ctv);
      config.append("    owner: root:root\n"_ctv);
      config.append("    permissions: '0600'\n"_ctv);
      config.append("    content: |\n"_ctv);
      for (uint64_t index = 0; index < hostKeyPackage.privateKeyOpenSSH.size(); ++index)
      {
         config.append("      "_ctv);
         while (index < hostKeyPackage.privateKeyOpenSSH.size())
         {
            uint8_t ch = hostKeyPackage.privateKeyOpenSSH[index];
            ++index;
            if (ch == '\n')
            {
               break;
            }

            if (ch != '\r')
            {
               config.append(ch);
            }
         }
         config.append("\n"_ctv);
      }

      config.append("  - path: /etc/ssh/ssh_host_ed25519_key.pub\n"_ctv);
      config.append("    owner: root:root\n"_ctv);
      config.append("    permissions: '0644'\n"_ctv);
      config.append("    content: |\n"_ctv);
      config.append("      "_ctv);
      config.append(hostKeyPackage.publicKeyOpenSSH);
      config.append("\n"_ctv);
   }

   config.append("runcmd:\n"_ctv);
   if (rootUser)
   {
      config.append("  - mkdir -p /root/.ssh\n"_ctv);
      config.append("  - chmod 700 /root/.ssh\n"_ctv);
      config.append("  - chmod 600 /root/.ssh/authorized_keys || true\n"_ctv);
   }
   else
   {
      config.append("  - mkdir -p /home/"_ctv);
      config.append(sshUser);
      config.append("/.ssh\n"_ctv);
      config.append("  - chown -R "_ctv);
      config.append(sshUser);
      config.append(":"_ctv);
      config.append(sshUser);
      config.append(" /home/"_ctv);
      config.append(sshUser);
      config.append("/.ssh || true\n"_ctv);
      config.append("  - chmod 700 /home/"_ctv);
      config.append(sshUser);
      config.append("/.ssh || true\n"_ctv);
      config.append("  - chmod 600 /home/"_ctv);
      config.append(sshUser);
      config.append("/.ssh/authorized_keys || true\n"_ctv);
   }
   config.append("  - systemctl restart sshd || systemctl restart ssh || service sshd restart || service ssh restart\n"_ctv);
}

static inline void prodigyAppendEscapedJSONStringLiteral(String& output, const String& value)
{
   output.append('"');

   for (uint64_t index = 0; index < value.size(); ++index)
   {
      uint8_t byte = value[index];

      switch (byte)
      {
         case '\\':
         {
            output.append("\\\\"_ctv);
            break;
         }
         case '"':
         {
            output.append("\\\""_ctv);
            break;
         }
         case '\n':
         {
            output.append("\\n"_ctv);
            break;
         }
         case '\r':
         {
            output.append("\\r"_ctv);
            break;
         }
         case '\t':
         {
            output.append("\\t"_ctv);
            break;
         }
         default:
         {
            output.append(byte);
            break;
         }
      }
   }

   output.append('"');
}
