using EncryptionSafe.Encryption;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptonView.Models
{
    public class EncryptedRecordDataModel<T> : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged = delegate { };

        public string Display { get; set; }
        public string OpenDataText { get { return OpenData?.ToString(); } }
        public T OpenData { get; set; }
        public string Key { get { return _encrypted.Dictionary[PairingKey + "_key"].Active; } }
        public string Secret { get { return _encrypted.Dictionary[PairingKey + "_secret"].Active; } }
        /// <summary>
        /// Key to pair encrypted record with open data
        /// </summary>
        public string PairingKey { get; private set; }

        public EncryptedType EncryptedState { get { return _encrypted.Dictionary[PairingKey + "_key"].EncryptionState; } }

        private EncryptedDictionary _encrypted;

        public EncryptedRecordDataModel(EncryptedDictionary encrypted)
        {
            _encrypted = encrypted;
        }

        public EncryptedRecordDataModel(EncryptedDictionary encrypted, string display, T openData, string pairingKey)
        {
            _encrypted = encrypted;
            Display = display;
            OpenData = openData;
            PairingKey = pairingKey;
        }

        public void Decrypt()
        {
            _encrypted.Dictionary[PairingKey + "_key"].Decrypt<string>(_encrypted.EncryptionService, _encrypted.KeyPassword);
            _encrypted.Dictionary[PairingKey + "_secret"].Decrypt<string>(_encrypted.EncryptionService, _encrypted.KeyPassword);
            NotifyEncryptionChange();
        }

        public void Encrypt()
        {
            _encrypted.Dictionary[PairingKey + "_key"].ComputePartEncryption(_encrypted.EncryptionService, _encrypted.KeyPassword);
            _encrypted.Dictionary[PairingKey + "_secret"].ComputePartEncryption(_encrypted.EncryptionService, _encrypted.KeyPassword);
            NotifyEncryptionChange();
        }

        public static EncryptedRecordDataModel<T> Create(EncryptedDictionary encrypted, string display, string key, string secret, T openData)
        {
            var result = new EncryptedRecordDataModel<T>(encrypted);
            var rnd = new Random();
            string newPairingKey = null;
            do
            {
                newPairingKey = rnd.Next(int.MaxValue).ToString();
            } while (encrypted.Dictionary.ContainsKey(newPairingKey));
            result.PairingKey = newPairingKey;
            result.Display = display;
            encrypted.Dictionary.Add(newPairingKey + "_key", new EncryptedNode() { Original = key });
            encrypted.Dictionary.Add(newPairingKey + "_secret", new EncryptedNode() { Original = secret });
            result.OpenData = openData;
            return result;
        }

        public void NotifyEncryptionChange()
        {
            foreach (var value in new string[] { nameof(Key), nameof(Secret), nameof(EncryptedState) }){
                PropertyChanged(this, new PropertyChangedEventArgs(value));
            }
        }

    }
}
