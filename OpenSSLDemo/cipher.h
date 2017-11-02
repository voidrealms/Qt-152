#ifndef CIPHER_H
#define CIPHER_H

#include <QObject>
#include <QDebug>
#include <QFile>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// The PADDING parameter means RSA will pad your data for you
//#define PADDING RSA_PKCS1_OAEP_PADDING
//#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING
#define PADDING RSA_PKCS1_PADDING
#define KEYSIZE 32
#define IVSIZE 32
#define BLOCKSIZE 256
#define SALTSIZE 8

/**
 * @brief Wraps the RSA and AES Crypto functions of OpenSSL
 * @details Compatible with the OpenSSL command line
 *
 *    Same as:
 *    openssl aes-256-cbc -salt -md sha1 -in file.txt -out file.enc -pass pass:password
 *    openssl aes-256-cbc -d -salt -md sha1 -in file.enc -out file.txt -pass pass:password
 *
 *    Be sure to link to the OpenSSL Lib and include the headers:
 *
 *    INCLUDEPATH += ../Libraries/openssl/include
 *    LIBS += ../Libraries/openssl/libcrypto.a
 *    LIBS += ../Libraries/openssl/libssl.a
 *
 */
class Cipher : public QObject
{
    Q_OBJECT
public:
    explicit Cipher(QObject *parent = 0);
    ~Cipher();

    /**
     * @brief Loads the public key from a byte array
     * @param data The byte array
     * @return RSA
     */
    RSA *getPublicKey(QByteArray &data);

    /**
     * @brief Loads the public key from a file
     * @param filename The file to load
     * @return RSA
     */
    RSA *getPublicKey(QString filename);

    /**
     * @brief Loads the private key from a byte array
     * @param data The byte array
     * @return RSA
     */
    RSA *getPrivateKey(QByteArray &data);

    /**
     * @brief Loads the private key from a file
     * @param filename The file to load
     * @return RSA
     */
    RSA *getPrivateKey(QString filename);

    /**
     * @brief Encrypts a byte array using the RSA public key
     * @param key The public key
     * @param data The data to encrypt
     * @return QByteArray
     */
    QByteArray encryptRSA(RSA *key, QByteArray &data);

    /**
     * @brief Decrypts a byte array using the RSA private key
     * @param key The private key
     * @param data The data to encrypt
     * @return QByteArray
     */
    QByteArray decryptRSA(RSA *key, QByteArray &data);

    /**
     * @brief Encrypt a byte array with AES 256 CBC
     * @param data The byte array to encrypt
     * @return QByteArray
     */
    QByteArray encryptAES(QByteArray passphrase, QByteArray &data);

    /**
     * @brief Decrypt a byte array with AES 256 CBC
     * @param data The byte array to decrypt
     * @return QByteArray
     */
    QByteArray decryptAES(QByteArray passphrase, QByteArray &data);

    /**
     * @brief Get a byte array filled with random information
     * @param size The size of the byte array to generate
     * @return QByteArray
     */
    QByteArray randomBytes(int size);

    /**
     * @brief Frees an RSA key from memory
     * @param key The RSA key
     */
    void freeRSAKey(RSA *key);

signals:

public slots:

private:
    /**
      * @brief Initalize the OpenSSL Lib
      */
    void initalize();

    /**
      * @brief Cleanup after the OpenSSL lib
      */
    void finalize();

    /**
     * @brief Loads a file and returns a byte array
     * @param filename The fiel to read from
     * @return QByteArray
     */
    QByteArray readFile(QString filename);

    /**
     * @brief Writes a byte array to a file
     * @param filename The name of the file to write to
     * @param data The byte array to write
     */
    void writeFile(QString filename, QByteArray &data);

};

#endif // CIPHER_H
