using EncryptionSafe.Encryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionTest
{
    public class FakeObject
    {
        public Dictionary<string, FakeItem> Dict { get; set; }

        public FakeObject(EncryptedDictionary encrypted)
        {
            Dict = new Dictionary<string, FakeItem>();
            Dict.Add("itemName", new FakeItem(encrypted) { Key = "localKey", Text = "Something" });
            Dict.Add("itemNameCopy", new FakeItem(encrypted) { Key = "localKeyCopy", Text = "Something" });
        }
    }

    public class FakeItem
    {
        public string Key { get; set; }
        public string Text { get; set; }
        public string Secret
        {
            get
            {
                return _encrypted.Dictionary[Key].Decrypt<string>(_encrypted.EncryptionService, _encrypted._keyPassword);
            }
            set
            {
                // This can throw exception when we don't have password in encrypted dictionary
                _encrypted.AddEncryptedRecord(Key, value);
            }
        }

        private EncryptedDictionary _encrypted { get; set; }

        public FakeItem(EncryptedDictionary encrypted)
        {
            _encrypted = encrypted;
        }
    }
}
