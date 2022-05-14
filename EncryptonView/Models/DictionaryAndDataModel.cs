using EncryptionSafe.Encryption;
using EncryptonView.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionView.Models
{
    public class DictionaryAndDataModel<T>
    {
        public List<OpenRecordDataModel<T>> OpenRecords { get; set; } = new List<OpenRecordDataModel<T>>();
        public EncryptedDictionary EncryptedDictionary { get; set; }

        public void Save(string filename)
        {
            EncryptedDictionary.EncryptAll();
            var text = JsonConvert.SerializeObject(this);
            using (var sw = new System.IO.StreamWriter(filename))
            {
                sw.Write(text);
                sw.Close();
            }
        }
        public void SaveWithoutEncrypt(string filename)
        {
            var text = JsonConvert.SerializeObject(this);
            using (var sw = new System.IO.StreamWriter(filename))
            {
                sw.Write(text);
                sw.Close();
            }
        }

        public void Load(string filename)
        {
            string text;
            using (var sr = new System.IO.StreamReader(filename))
            {
                text = sr.ReadToEnd();
                sr.Close();
            }
            var result = JsonConvert.DeserializeObject<DictionaryAndDataModel<T>>(text);
            OpenRecords = result?.OpenRecords ?? new List<OpenRecordDataModel<T>>();
            EncryptedDictionary = result?.EncryptedDictionary;
        }
    }
}
