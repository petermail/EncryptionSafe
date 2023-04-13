using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionSafe.Encryption
{
    public class EncryptionService
    {
        public int? IterationsPerMinute { get; set; }
        public int PasswordIterations { get; set; } = 10;
        public byte[] SaltValue { get; set; }
        public byte[] InitVector { get; set; }

        [JsonIgnore]
        public Action InitializationCallback { get; set; }

        private const string _hashAlgorithm = "SHA256";
        private const int _keySize = 256;

        public static EncryptionService _instance;
        public bool IsInitializationRunning { get; set; } = false;

        public EncryptionService()
        {
            SaltValue = GenerateRandomCryptographicKey(64);
            InitVector = GenerateRandomCryptographicKey(16);
        }

        public static EncryptionService Instance {
            get
            {
                if (_instance == null)
                {
                    _instance = new EncryptionService();
                    _instance.InitializeAsync().RunSynchronously();
                }
                return _instance;
            }
        }

        public async Task InitializeAsync()
        {
            if (IterationsPerMinute == null)
            {
                IsInitializationRunning = true;
                await Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(60000); // Wait a minute because initialization will usually start with start of the application that also starts lot of other tasks
                        IterationsPerMinute = CountIterationsPerMinute();
                        PasswordIterations = IterationsPerMinute.Value;
                    }
                    finally
                    {
                        IsInitializationRunning = false;
                    }

                    InitializationCallback?.Invoke();
                });
            }
        }

        public byte[] GetKeyInBytes(string password)
        {
            return RijndaelAlgorithm.GetKeyInBytes(password, SaltValue, _hashAlgorithm, PasswordIterations, _keySize);
        }
        public byte[] GetKeyInBytes(byte[] password)
        {
            return RijndaelAlgorithm.GetKeyInBytes(password, SaltValue, _hashAlgorithm, PasswordIterations, _keySize);
        }

        public byte[] GetIndividualKeyInBytes(byte[] keyPassword, byte[] individualSalt)
        {
            var password = Convert.ToBase64String(keyPassword);
            return RijndaelAlgorithm.GetKeyInBytes(password, individualSalt, _hashAlgorithm, 10, _keySize);
        }

        public string Encrypt(byte[] keyPassword, string text)
        {
            return RijndaelAlgorithm.Encrypt(text, InitVector, keyPassword);
        }

        public string Decrypt(string password, string encryptedText)
        {
            try
            {
                return RijndaelAlgorithm.Decrypt(encryptedText, password, SaltValue, _hashAlgorithm, PasswordIterations, InitVector, _keySize);
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        public string Decrypt(byte[] keyPassword, string encryptedText)
        {
            try
            {
                return RijndaelAlgorithm.Decrypt(encryptedText, InitVector, keyPassword);
            } catch (Exception ex)
            {
                return null;
            }
        }

        public string GenerateRandomCryptographicKeyString(int keyLength)
        {
            return Convert.ToBase64String(GenerateRandomCryptographicKey(keyLength));
        }
        public byte[] GenerateRandomCryptographicKey(int keyLength)
        {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLength];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            //return Convert.ToBase64String(randomBytes);
            //return Encoding.ASCII.GetString(randomBytes);
            return randomBytes;
        }

        private long PasswordHashingInMilliseconds(int iterations)
        {
            // First, we must create a password, from which the key will be derived.
            // This password will be generated from the specified passphrase and 
            // salt value. The password will be created using the specified hash 
            // algorithm. Password creation can be done in several iterations.
            var password = new Rfc2898DeriveBytes
            (
                "RandomPassordText",
                Encoding.ASCII.GetBytes("RandomSaltText"),
                //_hashAlgorithm,
                iterations
            );

            Stopwatch watch = new Stopwatch();
            watch.Start();

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(_keySize / 8);

            watch.Stop();
            return watch.ElapsedMilliseconds;
        }

        public int CountIterationsPerMinute()
        {
            long processedIterations = 0;
            long processedMilliseconds = 0;
            long activeIterations = 500;
            do
            {
                var milliseconds = PasswordHashingInMilliseconds((int)Math.Max(500, activeIterations));
                processedIterations += activeIterations;
                processedMilliseconds += milliseconds;

                var expectedIterationsToEnd = processedIterations * (1d - processedMilliseconds / 60000d);
                activeIterations = (int)Math.Min(activeIterations * activeIterations + 1, expectedIterationsToEnd / 2d);
            } while (processedMilliseconds <= 60000);
            return (int)processedIterations;
        }

        public static string AppendHashFile(string password, string filename)
        {
            return password + ";" + HashFile(filename);
        }
        public static string HashFile(string filename)
        {
            using (var stream = System.IO.File.OpenRead(filename))
            {
                using (var sha256 = SHA256.Create())
                {
                    var bytes = sha256.ComputeHash(stream);
                    return Convert.ToBase64String(bytes);
                }
            }
        }

        public void Save(string filename)
        {
            var text = Newtonsoft.Json.JsonConvert.SerializeObject(this);
            using (var sw = new System.IO.StreamWriter(filename))
            {
                sw.WriteLine(text);
                sw.Close();
            }
        }
        public static EncryptionService Load(string filename)
        {
            using (var sr = new System.IO.StreamReader(filename))
            {
                string text = sr.ReadToEnd();
                var result = Newtonsoft.Json.JsonConvert.DeserializeObject<EncryptionService>(filename);
                Task.Run(() => result.InitializeAsync());
                return result;
            }
        }
    }
}
