using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionSafe.Encryption
{
    public class RijndaelAlgorithm
    {
        public static byte[] GetKeyInBytes(string passPhrase, byte[] saltValueBytes, string hashAlgorithm, int passwordIterations, int keySize)
        {
            //byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

            // First, we must create a password, from which the key will be derived.
            // This password will be generated from the specified passphrase and 
            // salt value. The password will be created using the specified hash 
            // algorithm. Password creation can be done in several iterations.
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes
            (
                passPhrase,
                saltValueBytes,
                //hashAlgorithm,
                passwordIterations
            );

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(keySize / 8);
            return keyBytes;
        }

        public static byte[] GetKeyInBytes(byte[] passPhrase, byte[] saltValueBytes, string hashAlgorithm, int passwordIterations, int keySize)
        {
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, passwordIterations);

            byte[] keyBytes = password.GetBytes(keySize / 8);
            return keyBytes;
        }

        public static string Encrypt(string plainText, byte[] initVectorBytes, byte[] keyBytes)
        {
            // Convert strings into byte arrays.
            // Let us assume that strings only contain ASCII codes.
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
            // encoding.
            //byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);

            // Convert our plaintext into a byte array.
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // Create uninitialized Rijndael encryption object.
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;

            // Generate encryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key bytes.
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor
            (
                keyBytes,
                initVectorBytes
            );

            // Define memory stream which will be used to hold encrypted data.
            MemoryStream memoryStream = new MemoryStream();

            // Define cryptographic stream (always use Write mode for encryption).
            CryptoStream cryptoStream = new CryptoStream
            (
                memoryStream,
                encryptor,
                CryptoStreamMode.Write
            );

            // Start encrypting.
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

            // Finish encrypting.
            cryptoStream.FlushFinalBlock();

            // Convert our encrypted data from a memory stream into a byte array.
            byte[] cipherTextBytes = memoryStream.ToArray();

            // Close both streams.
            memoryStream.Close();
            cryptoStream.Close();

            // Convert encrypted data into a base64-encoded string.
            string cipherText = Convert.ToBase64String(cipherTextBytes);

            // Return encrypted string.
            return cipherText;
        }

        public static string Decrypt
        (
            string cipherText,
            string passPhrase,
            byte[] saltValueBytes,
            string hashAlgorithm,
            int passwordIterations,
            byte[] initVector,
            int keySize
        )
        {
            //byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

            // First, we must create a password, from which the key will be 
            // derived. This password will be generated from the specified passphrase and salt value. 
            // The password will be created using the specified hash algorithm. Password creation can be done in several iterations.
            var password = new Rfc2898DeriveBytes
            (
                passPhrase,
                saltValueBytes,
                //hashAlgorithm,
                passwordIterations
            );

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(keySize / 8);

            return Decrypt(cipherText, initVector, keyBytes);
        }
        public static string Decrypt(string cipherText, byte[] initVectorBytes, byte[] keyBytes)
        {
            // Convert strings defining encryption key characteristics into byte arrays. 
            //byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
            // Convert our ciphertext into a byte array.
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            // Create uninitialized Rijndael encryption object.
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining
            // (CBC). Use default options for other symmetric key parameters.
            symmetricKey.Mode = CipherMode.CBC;

            // Generate decryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes.
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor
            (
                keyBytes,
                initVectorBytes
            );

            // Define memory stream which will be used to hold encrypted data.
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

            // Define cryptographic stream (always use Read mode for encryption).
            CryptoStream cryptoStream = new CryptoStream
            (
                memoryStream,
                decryptor,
                CryptoStreamMode.Read
            );
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            // Start decrypting.
            int decryptedByteCount = cryptoStream.Read
            (
                plainTextBytes,
                0,
                plainTextBytes.Length
            );

            // Close both streams.
            memoryStream.Close();
            cryptoStream.Close();

            // Convert decrypted data into a string. 
            // Let us assume that the original plaintext string was UTF8-encoded.
            string plainText = Encoding.UTF8.GetString
            (
                plainTextBytes,
                0,
                decryptedByteCount
            );

            // Return decrypted string.   
            return plainText;
        }
    }
}
