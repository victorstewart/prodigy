#pragma once

#include <cstring>

#include <types/types.string.h>

static inline String prodigyTestSSHAssetPath(const char *filename)
{
   String path = {};

   const char *self = __FILE__;
   const char *slash = std::strrchr(self, '/');
   if (slash != nullptr)
   {
      path.assign(self, uint64_t(slash - self));
   }
   else
   {
      path.assign("."_ctv);
   }

   path.append("/assets/ssh/"_ctv);
   path.append(filename);
   return path;
}

static inline String prodigyTestClientSSHPrivateKeyPath(void)
{
   return prodigyTestSSHAssetPath("client_ed25519");
}

static inline String prodigyTestClientSSHPublicKeyPath(void)
{
   return prodigyTestSSHAssetPath("client_ed25519.pub");
}

static inline String prodigyTestBootstrapSeedSSHPrivateKeyPath(void)
{
   return prodigyTestSSHAssetPath("bootstrap_seed_ed25519");
}

static inline String prodigyTestBootstrapSeedSSHPublicKeyPath(void)
{
   return prodigyTestSSHAssetPath("bootstrap_seed_ed25519.pub");
}

static inline String prodigyTestSSHDHostPrivateKeyPath(void)
{
   return prodigyTestSSHAssetPath("sshd_host_ed25519");
}

static inline String prodigyTestSSHDHostPublicKeyPath(void)
{
   return prodigyTestSSHAssetPath("sshd_host_ed25519.pub");
}
