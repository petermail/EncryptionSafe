using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionSafe.Encryption
{
    /// <summary>
    /// Encrypted dictionary holding keys with encrypted nodes and encryption service
    /// </summary>
    public class EncryptedDictionary
    {
        /// <summary>
        /// Dictionary of encrypted nodes
        /// </summary>
        public Dictionary<string, EncryptedNode> Dictionary { get; set; }
        /// <summary>
        /// Encryption service used for all the nodes encryption
        /// </summary>
        public EncryptionService EncryptionService { get; set; }

        /// <summary>
        /// Hash of password
        /// </summary>
        [JsonIgnore]
        public byte[] KeyPassword { get; private set; }

        public EncryptedDictionary()
        {
            Dictionary = new Dictionary<string, EncryptedNode>();
        }

        /// <summary>
        /// Initialize encryption service if needed, the password initialization is done in a special thread and will take one minute
        /// </summary>
        public async Task InitializeAsync()
        {
            if (EncryptionService == null)
            {
                EncryptionService = new EncryptionService();
            }
            if (EncryptionService.IterationsPerMinute == null)
            {
                await EncryptionService.InitializeAsync();
            }
        }

        public void EncryptAll(byte[] password, Action callback = null)
        {
            EncryptAllPrivate(() => EncryptionService.GetKeyInBytes(password), callback);
        }

        /// <summary>
        /// Encrypt all data in the dictionary
        /// </summary>
        /// <param name="password">Password to use for encryption</param>
        /// <param name="callback">Callback to run after initialization (if needed) and encryption is finished</param>
        public void EncryptAll(string password, Action callback = null)
        {
            EncryptAllPrivate(() => EncryptionService.GetKeyInBytes(password), callback);
        }
        private void EncryptAllPrivate(Func<byte[]> getKeyInBytes, Action callback = null)
        {
            if (EncryptionService.IterationsPerMinute == null)
            {
                if (EncryptionService.IsInitializationRunning)
                {
                    EncryptionService.InitializationCallback = () => {
                        var keyPassword = getKeyInBytes();
                        EncryptAll(keyPassword);
                        callback?.Invoke();
                    };
                }
            }
            else
            {
                var keyPassword = getKeyInBytes();
                EncryptAll(keyPassword);
                callback?.Invoke();
            }
        }
        public void EncryptAll()
        {
            if (KeyPassword == null) { throw new Exception("Missing key password for encryption."); }
            EncryptAll(KeyPassword);
        }
        private void EncryptAll(byte[] keyPassword)
        {
            foreach (var dict in Dictionary) {
                dict.Value.ComputeFullEncryption(EncryptionService, keyPassword);
            }
        }
        /// <summary>
        /// Encrypt all that that were not yet encrypted
        /// </summary>
        /// <param name="password">Password to use for encryption</param>
        public void EncryptNotEncrypted(string password)
        {
            var keyPasssword = EncryptionService.GetKeyInBytes(password);
            EncryptNotEncrypted(keyPasssword);
        }
        private void EncryptNotEncrypted(byte[] keyPassword)
        {
            foreach (var dict in Dictionary)
            {
                if (dict.Value.Encrypted == null)
                {
                    dict.Value.ComputeFullEncryption(EncryptionService, keyPassword);
                }
            }
        }
        /// <summary>
        /// Clear key password and partial encryption which will require decryption of the password later
        /// </summary>
        public void ClearKeyAndPartialEncryption()
        {
            foreach (var dict in Dictionary)
            {
                if (dict.Value.Encrypted == null)
                {
                    dict.Value.ComputeFullEncryption(EncryptionService, KeyPassword);
                }
                if (dict.Value.Encrypted == null)
                {
                    throw new Exception("Value wasn't successfully decrypted.");
                }
                dict.Value.EncryptedPart = null;
            }
            KeyPassword = null;
        }
        /// <summary>
        /// Decrypt password into hash; it will take one minute
        /// </summary>
        /// <param name="password">Password to use for decryption</param>
        /// <param name="isStillValid">Function to indicate if calculated password is still valid and should be used</param>
        public void DecryptKey(string password, Func<bool> isStillValid = null)
        {
            var keyPassword = EncryptionService.GetKeyInBytes(password);
            if (isStillValid == null || isStillValid())
            {
                KeyPassword = keyPassword;
            }
        }
        /// <summary>
        /// Decrypt password into hash; it will take one minute
        /// </summary>
        /// <param name="password">Password to use for decryption</param>
        /// <param name="isStillValid">Function to indicate if calculated password is still valid and should be used</param>
        public void DecryptKey(byte[] password, Func<bool> isStillValid = null)
        {
            var keyPassword = EncryptionService.GetKeyInBytes(password);
            if (isStillValid == null || isStillValid())
            {
                KeyPassword = keyPassword;
            }
        }
        /// <summary>
        /// Partially decrypt all data; if password wasn't converted into hash, it will take one minute
        /// </summary>
        /// <param name="password">Password to use for encryption; not needed if hash was already created before</param>
        public void DecryptPart(string password = null)
        {
            if (KeyPassword == null) { DecryptKey(password); }
            foreach (var dict in Dictionary)
            {
                if (dict.Value.Encrypted != null)
                {
                    dict.Value.DecryptPart(EncryptionService, KeyPassword);
                }
            }
        }
        /// <summary>
        /// Add encrypted record if we already decrypted password before
        /// </summary>
        /// <param name="key">Key to use for dictionary</param>
        /// <param name="original">Original value to encrypt</param>
        public void AddEncryptedRecord<T>(string key, T original)
        {
            if (KeyPassword == null)
            {
                throw new Exception("Can not encrypt newly added record.");
            }
            var newNode = new EncryptedNode() { Original = original };
            newNode.ComputeFullEncryption(EncryptionService, KeyPassword);
            Dictionary.Add(key, newNode);
        }

        public T GetDecryptedRecord<T>(string key, Func<string, T> convert = null)
        {
            if (KeyPassword == null)
            {
                throw new Exception("Can not decrypt record");
            }
            var first = Dictionary.FirstOrDefault(x => x.Key == key);
            if (first.Key == key) {
                first.Value.DecryptPart(EncryptionService, KeyPassword);
                var res = first.Value.Decrypt(EncryptionService, KeyPassword, convert);
                first.Value.ComputeFullEncryption(EncryptionService, KeyPassword);
                return res;
            } else { return default(T); }
        }

        /// <summary>
        /// Prepare data for saving. This will delete data that are not maximally encrypted
        /// </summary>
        public void PrepareForSaving()
        {
            foreach (var value in this.Dictionary.Values)
            {
                if (value.Encrypted == null)
                {
                    value.ComputeFullEncryption(EncryptionService, KeyPassword);
                }
                value.EncryptedPart = null;
                value.Original = null;
            }
            KeyPassword = null;
        }
        /// <summary>
        /// Save data encrypted data if everything is in encrypted format only
        /// </summary>
        /// <param name="filename">Filename of json file to save the encrypted data into</param>
        public void Save(string filename)
        {
            if (this.Dictionary.Values.Any(x => x.Encrypted == null))
            {
                throw new Exception("You try to save non encrypted data.");
            }
            var text = JsonConvert.SerializeObject(this);
            using (var sw = new System.IO.StreamWriter(filename))
            {
                sw.WriteLine(text);
                sw.Close();
            }
        }
        /// <summary>
        /// Load or create new encrypted dictionary and initialize password if needed (json format)
        /// </summary>
        /// <param name="filename">Filename of json encrypted dictionary</param>
        /// <returns>Encrypted dictionary</returns>
        public static async Task<EncryptedDictionary> LoadOrCreate(string filename)
        {
            EncryptedDictionary result = null;
            if (System.IO.File.Exists(filename))
            {
                using (var sr = new System.IO.StreamReader(filename))
                {
                    string text = sr.ReadToEnd();
                    result = JsonConvert.DeserializeObject<EncryptedDictionary>(text);
                    if (result != null && result.EncryptionService.IterationsPerMinute == null)
                    {
                        await result.InitializeAsync();
                    }
                }
            }
            if (result == null)
            {
                result = new EncryptedDictionary();
                await result.InitializeAsync();
            }
            return result;
        }
        public static EncryptedDictionary Load(string filename)
        {
            if (System.IO.File.Exists(filename))
            {
                using (var sr = new System.IO.StreamReader(filename))
                {
                    string text = sr.ReadToEnd();
                    return JsonConvert.DeserializeObject<EncryptedDictionary>(text);
                }
            }
            return null;
        }
        public static EncryptedDictionary Create(int iterations)
        {
            var result = new EncryptedDictionary();
            result.EncryptionService = new EncryptionService();
            result.EncryptionService.IterationsPerMinute = iterations;
            return result;
        }
    }

    /// <summary>
    /// Encryption node holding original data, partially encrypted/decrypted text or fully encrypted text and salt for first layer encryption
    /// </summary>
    public class EncryptedNode
    {
        [JsonIgnore]
        public object Original { get; set; }

        /// <summary>
        /// Encrypted data
        /// </summary>
        public string Encrypted { get; set; } = null;

        /// <summary>
        /// Data that are only partialy encrypted
        /// </summary>
        [JsonIgnore]
        public string EncryptedPart { get; set; } = null;

        /// <summary>
        /// Get active format of the data from the most decrypted first
        /// </summary>
        [JsonIgnore]
        public string Active { get { return Original?.ToString() ?? (EncryptedPart ?? Encrypted ?? null); } }

        /// <summary>
        /// Salt used for encryption of the partial encryption
        /// </summary>
        public byte[] Salt { get; set; }

        /// <summary>
        /// Encryption state of the data; i.e. what is the most decrypted data present
        /// </summary>
        public EncryptedType EncryptionState
        {
            get
            {
                return Original != null ? EncryptedType.None
                    : (EncryptedPart != null ? EncryptedType.EncryptedPartialy : EncryptedType.FullyEncrypted);
            }
        }

        public EncryptedNode() { }

        /// <summary>
        /// Compute full encryption of the original data
        /// </summary>
        /// <param name="encryptionService">Encryption service to use for encryption</param>
        /// <param name="keyPassword">Hash of main password</param>
        public void ComputeFullEncryption(EncryptionService encryptionService, byte[] keyPassword)
        {
            if (Original != null)
            {
                ComputePartEncryption(encryptionService, keyPassword);

                ComputeRestOfEncryption(encryptionService, keyPassword);
            }
        }
        /// <summary>
        /// Compute partial encryption of the original data based on individual key derived from hash of main password and <see cref="Salt"/>
        /// </summary>
        /// <param name="encryptionService">Encryption service to use for encryption</param>
        /// <param name="keyPassword">Hash of main password</param>
        public void ComputePartEncryption(EncryptionService encryptionService, byte[] keyPassword)
        {
            if (Original != null)
            {
                if (Salt == null)
                {
                    Salt = encryptionService.GenerateRandomCryptographicKey(32);
                }
                var newKeyPassword = encryptionService.GetIndividualKeyInBytes(keyPassword, Salt);
                EncryptedPart = encryptionService.Encrypt(newKeyPassword, Original.ToString());

                var check = encryptionService.Decrypt(newKeyPassword, EncryptedPart);
                if (check != Original.ToString()) { throw new Exception("Can not be decrypted."); }

                Original = null;
            }
        }
        /// <summary>
        /// Compute rest of encryption of the partially encrypted data
        /// </summary>
        /// <param name="encryptionService">Encryption service to use for encryption</param>
        /// <param name="keyPassword">Hash of main password</param>
        public void ComputeRestOfEncryption(EncryptionService encryptionService, byte[] keyPassword)
        {
            Encrypted = encryptionService.Encrypt(keyPassword, EncryptedPart);

            var check = encryptionService.Decrypt(keyPassword, Encrypted);
            if (check != EncryptedPart) { throw new Exception("Can not be decrypted, step 2."); }
        }

        /// <summary>
        /// Decrypt first part of encryption layer
        /// </summary>
        /// <param name="encryptionService">Encryption service to use for decryption</param>
        /// <param name="keyPassword">Hash of main password</param>
        public void DecryptPart(EncryptionService encryptionService, byte[] keyPassword)
        {
            EncryptedPart = encryptionService.Decrypt(keyPassword, Encrypted);
        }
        /// <summary>
        /// Decrypt the original data from only partially encrypted/decrypted data
        /// </summary>
        /// <typeparam name="T">Type of result</typeparam>
        /// <param name="encryptionService">Encryption service to use for decryption</param>
        /// <param name="keyPassword">Hash of main password</param>
        /// <param name="convert">Converter from decrypted string into type T; not needed to specify if result is string, int, double or bool</param>
        /// <returns>Decrypted data of type T</returns>
        public T Decrypt<T>(EncryptionService encryptionService, byte[] keyPassword, Func<string, T> convert = null)
        {
            T result = default(T);
            if (EncryptedPart != null)
            {
                if (Salt == null)
                {
                    Salt = encryptionService.GenerateRandomCryptographicKey(32);
                }
                var individualKeyPassword = encryptionService.GetIndividualKeyInBytes(keyPassword, Salt);
                var decryptedPart = encryptionService.Decrypt(individualKeyPassword, EncryptedPart);
                if (typeof(T) == typeof(string))
                {
                    result = (T)Convert.ChangeType(decryptedPart, typeof(string));
                } else if (typeof(T) == typeof(int))
                {
                    result = (T)Convert.ChangeType(decryptedPart, typeof(int));
                } else if (typeof(T) == typeof(double))
                {
                    result = (T)Convert.ChangeType(decryptedPart, typeof(double));
                } else if (typeof(T) == typeof(bool))
                {
                    result = (T)Convert.ChangeType(decryptedPart, typeof(bool));
                } else if (convert != null)
                {
                    result = convert(decryptedPart);
                }
            }
            Original = result;
            return result;
        }
    }

    public enum EncryptedType
    {
        None = 0,
        EncryptedPartialy = 1,
        FullyEncrypted = 2
    }
}
