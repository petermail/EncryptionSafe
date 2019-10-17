using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptonView.Models
{
    public class OpenRecordDataModel<T>
    {
        public string Display { get; set; }
        public T OpenData { get; set; }
        public string PairingKey { get; set; }
    }
}
