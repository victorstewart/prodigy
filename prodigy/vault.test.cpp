#include <services/vault.h>
#include <services/debug.h>
#include <openssl/pem.h>

// clang++ -stdlib=libc++ -std=gnu++20 -fuse-ld=lld -Xlinker -v -I/root/openssl-openssl-3.0.7/include -I/root/nametag -I/root/nametag/libraries/include -I/usr/local/include/c++/v1 -I/usr/local/include/x86_64-unknown-linux-gnu/c++/v1 /usr/local/lib/x86_64-unknown-linux-gnu/libc++.so /root/openssl-openssl-3.0.7/libssl.so /root/openssl-openssl-3.0.7/libcrypto.so -Wno-gnu-string-literal-operator-template -Wno-c99-designator vault.test.cpp -o vault.test

int main()
{
	X509 *rootCert = NULL;
	EVP_PKEY *rootKey = NULL;
	VaultCertificateRequest rootRequest = {};
	rootRequest.type = CertificateType::root;
	rootRequest.scheme = CryptoScheme::p256;
	generateCertificateAndKeys(rootRequest, NULL, NULL, rootCert, rootKey);

	X509 *interCert = NULL;
	EVP_PKEY *interKey = NULL;
	VaultCertificateRequest intermediateRequest = {};
	intermediateRequest.type = CertificateType::intermediary;
	intermediateRequest.scheme = CryptoScheme::p256;
	generateCertificateAndKeys(intermediateRequest, rootCert, rootKey, interCert, interKey);

	X509 *serverCert = NULL;
	EVP_PKEY *serverKey = NULL;
	VaultCertificateRequest serverRequest = {};
	serverRequest.type = CertificateType::server;
	serverRequest.scheme = CryptoScheme::p256;
	serverRequest.enableServerAuth = true;
	generateCertificateAndKeys(serverRequest, interCert, interKey, serverCert, serverKey);

	X509 *clientCert = NULL;
	EVP_PKEY *clientKey = NULL;
	VaultCertificateRequest clientRequest = {};
	clientRequest.type = CertificateType::client;
	clientRequest.scheme = CryptoScheme::p256;
	clientRequest.enableClientAuth = true;
	generateCertificateAndKeys(clientRequest, interCert, interKey, clientCert, clientKey);


	// int i2d_PrivateKey_bio(BIO *bp, const EVP_PKEY *pkey);
	// int i2d_PrivateKey_fp(FILE *fp, const EVP_PKEY *pkey);

	//  int i2d_X509_bio(BIO *bp, X509 *x);
 	//  int i2d_X509_fp(FILE *fp, X509 *x);

	auto writeCertToDisk = [&] (const char *label, X509 *cert, const char *path) -> void {

		FILE *fp = fopen(path, "w+");
		// int result = i2d_X509_fp(fp, cert);

		int result = PEM_write_X509(
	       fp,   /* write the certificate to the file we've opened */
	       cert /* our certificate */
	   );

		basics_log("%s -> result = %d\n", label, result);

		fclose(fp);
	};

	auto writeKeyToDisk = [&] (const char *label, const EVP_PKEY *key, const char *path) -> void {

		FILE *fp = fopen(path, "w+");

		int result = PEM_write_PrivateKey(
	       fp,                          /* write the key to the file we've opened */
	       key,                       /* our key from earlier */
	       NULL,          /* default cipher for encrypting the key on disk */
	       NULL,      /* passphrase required for decrypting the key on disk */
	       0,                          /* length of the passphrase string */
	       NULL,                       /* callback for requesting a password */
	       NULL                        /* data to pass to the callback */
	   );

		// int result = i2d_PrivateKey_fp(fp, key);

		basics_log("%s -> result = %d\n", label, result);
		
		fclose(fp);
	};

	writeCertToDisk("root cert", rootCert, "/root/nametag/infrastructure/test.root.cert.pem");
	writeKeyToDisk("root key", rootKey, "/root/nametag/infrastructure/test.root.key.pem");

	writeCertToDisk("inter cert", interCert, "/root/nametag/infrastructure/test.inter.cert.pem");
	writeKeyToDisk("inter key", interKey, "/root/nametag/infrastructure/test.inter.key.pem");

	writeCertToDisk("server cert", serverCert, "/root/nametag/infrastructure/test.server.cert.pem");
	writeKeyToDisk("server key", serverKey, "/root/nametag/infrastructure/test.server.key.pem");

	writeCertToDisk("client cert", clientCert, "/root/nametag/infrastructure/test.client.cert.pem");
	writeKeyToDisk("client key", clientKey, "/root/nametag/infrastructure/test.client.key.pem");

	return 0;
}
