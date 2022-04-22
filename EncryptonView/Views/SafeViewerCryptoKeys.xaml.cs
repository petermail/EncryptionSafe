using EncryptionSafe.Encryption;
using EncryptonView.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace EncryptonView.Views
{
    /// <summary>
    /// Interaction logic for SafeViewer.xaml
    /// </summary>
    public partial class SafeViewerCryptoKeys : UserControl
    {
        public SafeViewerCryptoKeysViewModel ViewModel { get; set; }

        public SafeViewerCryptoKeys()
        {
            InitializeComponent();

            ViewModel = new SafeViewerCryptoKeysViewModel();
            ViewModel.ClearPassword = () => { this.Dispatcher.Invoke(() => PasswordBox1.Clear()); };
            DataContext = ViewModel;
        }

        private void ButtonActiveStateAction_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.DoActiveStateAction(PasswordBox1.SecurePassword);
        }

        private void ButtonAdd_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.AddNewRecord();
        }

        private void ButtonDecryptRecord_Click(object sender, RoutedEventArgs e)
        {
            var row = ((FrameworkElement)sender).DataContext as EncryptedRecordDataModel<OpenCryptoKeysData>;
            if (row.EncryptedState == EncryptedType.None)
            {
                row.Encrypt();
            }
            else
            {
                row.Decrypt();
            }
        }

        private void ButtonDeleteRecord_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Are you sure you want to delete selected row?", "Delete", MessageBoxButton.YesNoCancel) == MessageBoxResult.Yes)
            {
                var row = ((FrameworkElement)sender).DataContext as EncryptedRecordDataModel<OpenCryptoKeysData>;
                ViewModel.DeleteRecord(row);
            }
        }
    }

    public class SafeViewerCryptoKeysViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged = delegate { };

        private string _actionButtonText;
        public string ActionButtonText
        {
            get { return _actionButtonText; }
            set
            {
                _actionButtonText = value;
                PropertyChanged(this, new PropertyChangedEventArgs(nameof(ActionButtonText)));
            }
        }
        private bool _isActionEnabled = true;
        public bool IsActionEnabled { get { return _isActionEnabled; }
            set {
                _isActionEnabled = value;
                PropertyChanged(this, new PropertyChangedEventArgs(nameof(IsActionEnabled)));
            }
        }
        private int _iterations;
        public int Iterations { get { return _iterations; }
            set
            {
                _iterations = value;
                PropertyChanged(this, new PropertyChangedEventArgs(nameof(IterationsText)));
            }
        }
        public string IterationsText {
            get {
                return _iterations >= 1000000 ? string.Format("{0} mil.", _iterations / 1000000)
                    : ((int)(_iterations / 1000) * 1000).ToString();
            }
        }
        private bool _isUnlocked = false;
        public bool IsUnlocked { get { return _isUnlocked; }
            set {
                _isUnlocked = value;
                PropertyChanged(this, new PropertyChangedEventArgs(nameof(IsUnlocked)));
            }
        }
        public ObservableCollection<EncryptedRecordDataModel<OpenCryptoKeysData>> Records { get; set; }
        public List<OpenRecordDataModel<OpenCryptoKeysData>> OpenRecords { get; set; }
        public string Display { get; set; }
        public string Key { get; set; }
        public string Secret { get; set; }
        public string Passphrase { get; set; }
        public string IPs { get; set; }
        public DateTime ExpireDate { get; set; }
        public bool CanTrade { get; set; }
        public bool CanWithdraw { get; set; }
        public bool UseExpireDate { get; set; }
        public ObservableCollection<string> Exchanges { get; set; }

        public Action ClearPassword { get; set; }

        public EncryptedDictionary EncryptedDictionary { get; set; }

        public string FilenameSecret { get; set; } = "secrets.json";
        public string FilenameOpen { get; set; } = "open_data.json";

        public Action OnEncryption { get; set; }
        public Action OnDecryption { get; set; }

        private const string ACTION_DECRYPT = "Decrypt";
        private const string ACTION_STOP = "Stop";
        private const string ACTION_ENCRYPT = "Encrypt";
        private const string ACTION_WAIT = "Initialization";

        private Task _encryptionTask;
        private int _taskId = 0;
        
        public SafeViewerCryptoKeysViewModel()
        {
            OpenRecords = new List<OpenRecordDataModel<OpenCryptoKeysData>>();
            Records = new ObservableCollection<EncryptedRecordDataModel<OpenCryptoKeysData>>();
            ActionButtonText = ACTION_DECRYPT;
            EncryptedDictionary = EncryptedDictionary.LoadOrCreate(FilenameSecret).Result;
            if (EncryptedDictionary.EncryptionService.IsInitializationRunning)
            {
                ActionButtonText = ACTION_WAIT;
                IsActionEnabled = false;
                EncryptedDictionary.EncryptionService.InitializationCallback = () =>
                {
                    ActionButtonText = ACTION_DECRYPT;
                    IsActionEnabled = true;
                    Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
                    EncryptedDictionary.Save(FilenameSecret);
                };
            } else
            {
                Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
                foreach (var value in EncryptedDictionary.Dictionary)
                {
                    var keySecret = value.Key.Split('_');
                    if (keySecret.Length > 1 && keySecret[1] == "key")
                    {
                        var secret = keySecret[0];
                        Records.Add(new EncryptedRecordDataModel<OpenCryptoKeysData>(EncryptedDictionary, null, null, secret));
                    }
                }
                LoadOpenRecords(FilenameOpen);
                foreach (var openRecord in OpenRecords)
                {
                    var encrypted = Records.FirstOrDefault(x => x.PairingKey == openRecord.PairingKey);
                    if (encrypted != null)
                    {
                        encrypted.OpenData = openRecord.OpenData;
                        encrypted.Display = openRecord.Display;
                    }
                }
            }
            Exchanges = new ObservableCollection<string>();
        }

        public void Initialize(List<string> exchanges)
        {
            foreach (var exchange in exchanges)
            {
                Exchanges.Add(exchange);
            }
        }

        public void DeleteRecord(EncryptedRecordDataModel<OpenCryptoKeysData> record)
        {
            for (int i = OpenRecords.Count - 1; i >= 0; --i)
            {
                if (OpenRecords[i].PairingKey == record.PairingKey)
                {
                    OpenRecords.RemoveAt(i);
                    break;
                }
            }
            SaveOpenRecords(FilenameOpen);
            for (int i = Records.Count - 1; i >= 0; --i)
            {
                if (Records[i].PairingKey == record.PairingKey)
                {
                    Records.RemoveAt(i);
                    break;
                }
            }
            record.Remove();
            EncryptedDictionary.Save(FilenameSecret);
        }

        public bool IsAtLeastOneDecrypted()
        {
            bool result = false;
            foreach (var record in Records)
            {
                string key = record.Key;
                result = key != record.GetDecryptedKey();
                if (result) { break; }
            }
            return result;
        }

        public void DoActiveStateAction(SecureString password)
        {
            switch (ActionButtonText)
            {
                case ACTION_DECRYPT:
                    if (password.Length > 0)
                    {
                        ActionButtonText = ACTION_STOP;
                        var localTaskId = _taskId;
                        _encryptionTask = Task.Run(() =>
                        {
                            var pwd = new System.Net.NetworkCredential(string.Empty, password).Password;
                            EncryptedDictionary.DecryptKey(pwd, () => localTaskId == _taskId);
                            if (ActionButtonText == ACTION_STOP && localTaskId == _taskId)
                            {
                                ActionButtonText = ACTION_ENCRYPT;
                                var wasAnyNotEncrypted = EncryptedDictionary.Dictionary.Values.Any(x => x.Encrypted == null);
                                EncryptedDictionary.DecryptPart();
                                foreach (var record in Records)
                                {
                                    record.NotifyEncryptionChange();
                                }
                                if (wasAnyNotEncrypted)
                                {
                                    EncryptedDictionary.Save(FilenameSecret);
                                    SaveOpenRecords(FilenameOpen);
                                }
                                IsUnlocked = true;
                                ClearPassword?.Invoke();
                            }
                        }).ContinueWith(x => OnDecryption());
                    }
                    break;
                case ACTION_STOP:
                    if (_encryptionTask != null)
                    {
                        ++_taskId;
                        _encryptionTask = null;
                        ActionButtonText = ACTION_DECRYPT;
                    }
                    break;
                case ACTION_ENCRYPT:
                    ActionButtonText = ACTION_DECRYPT;
                    EncryptedDictionary.EncryptAll();
                    EncryptedDictionary.ClearKeyAndPartialEncryption();
                    IsUnlocked = false;
                    foreach (var record in Records)
                    {
                        record.NotifyEncryptionChange();
                    }
                    OnEncryption();
                    break;
            }
        }

        public void AddNewRecord()
        {
            var openData = new OpenCryptoKeysData() { CanTrade = CanTrade, CanWithdraw = CanWithdraw, IPs = IPs, Passphrase = Passphrase };
            if (UseExpireDate)
            {
                openData.ExpireDate = ExpireDate;
            }
            var encrypted = EncryptedRecordDataModel<OpenCryptoKeysData>.Create(EncryptedDictionary, Display, Key ?? string.Empty, Secret ?? string.Empty, openData);
            Records.Add(encrypted);
            if (EncryptedDictionary.KeyPassword != null)
            {
                EncryptedDictionary.EncryptAll();
                EncryptedDictionary.Save(FilenameSecret);
                OpenRecords.Add(new OpenRecordDataModel<OpenCryptoKeysData>() { Display = Display, PairingKey = encrypted.PairingKey, OpenData = openData });
                SaveOpenRecords(FilenameOpen);
            }

            Display = Key = Secret = Passphrase = IPs = null;
            UseExpireDate = CanTrade = CanWithdraw = false;
            foreach (var value in new string[] { nameof(Display), nameof(Key), nameof(Secret), nameof(Passphrase), nameof(IPs),
                nameof(UseExpireDate), nameof(CanTrade), nameof(CanWithdraw) })
            {
                PropertyChanged(this, new PropertyChangedEventArgs(value));
            }
        }

        public void SaveOpenRecords(string filename)
        {
            var text = JsonConvert.SerializeObject(OpenRecords);
            using (var sw = new System.IO.StreamWriter(filename))
            {
                sw.WriteLine(text);
                sw.Close();
            }
        }
        public void LoadOpenRecords(string filename)
        {
            if (System.IO.File.Exists(filename))
            {
                using (var sr = new System.IO.StreamReader(filename))
                {
                    var text = sr.ReadToEnd();
                    OpenRecords = JsonConvert.DeserializeObject<List<OpenRecordDataModel<OpenCryptoKeysData>>>(text);
                }
            }
            if (OpenRecords == null) { OpenRecords = new List<OpenRecordDataModel<OpenCryptoKeysData>>(); }
        }
    }

    public class OpenCryptoKeysData
    {
        public string IPs { get; set; }
        public DateTime? ExpireDate { get; set; }
        public bool CanTrade { get; set; }
        public bool CanWithdraw { get; set; }
        public string Passphrase { get; set; }

    }
}
