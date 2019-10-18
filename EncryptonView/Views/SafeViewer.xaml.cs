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
    public partial class SafeViewer : UserControl
    {
        public SafeViewerViewModel ViewModel { get; set; }

        public SafeViewer()
        {
            InitializeComponent();

            ViewModel = new SafeViewerViewModel();
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
            var row = ((FrameworkElement)sender).DataContext as EncryptedRecordDataModel<object>;
            if (row.EncryptedState == EncryptedType.None)
            {
                row.Encrypt();
            }
            else
            {
                row.Decrypt();
            }
        }
    }

    public class SafeViewerViewModel : INotifyPropertyChanged
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
        public ObservableCollection<EncryptedRecordDataModel<object>> Records { get; set; }
        public List<OpenRecordDataModel<object>> OpenRecords { get; set; }
        public string Display { get; set; }
        public string Key { get; set; }
        public string Secret { get; set; }

        public Action ClearPassword { get; set; }

        public EncryptedDictionary EncryptedDictionary { get; set; }

        private const string ACTION_DECRYPT = "Decrypt";
        private const string ACTION_STOP = "Stop";
        private const string ACTION_ENCRYPT = "Encrypt";
        private const string ACTION_WAIT = "Initialization";

        private Task _encryptionTask;
        private int _taskId = 0;
        
        public SafeViewerViewModel()
        {
            OpenRecords = new List<OpenRecordDataModel<object>>();
            Records = new ObservableCollection<EncryptedRecordDataModel<object>>();
            ActionButtonText = ACTION_DECRYPT;
            EncryptedDictionary = EncryptedDictionary.LoadOrCreate("secrets.json");
            if (EncryptedDictionary.EncryptionService.IsInitializationRunning)
            {
                ActionButtonText = ACTION_WAIT;
                IsActionEnabled = false;
                EncryptedDictionary.EncryptionService.InitializationCallback = () =>
                {
                    ActionButtonText = ACTION_DECRYPT;
                    IsActionEnabled = true;
                    Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
                    EncryptedDictionary.Save("secrets.json");
                };
            } else
            {
                Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
                foreach (var value in EncryptedDictionary.Dictionary)
                {
                    var keySecret = value.Key.Split('_');
                    if (keySecret.Length > 1 && keySecret[1] == "key")
                    {
                        Records.Add(new EncryptedRecordDataModel<object>(EncryptedDictionary, null, null, keySecret[0]));
                    }
                }
                LoadOpenRecords("open_data.json");
                // TO-DO: pair encrypted records with open records
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
                                var wasAnyNotEncryptd = EncryptedDictionary.Dictionary.Values.Any(x => x.Encrypted == null);
                                EncryptedDictionary.DecryptPart();
                                foreach (var record in Records)
                                {
                                    record.NotifyEncryptionChange();
                                }
                                if (wasAnyNotEncryptd)
                                {
                                    EncryptedDictionary.Save("secrets.json");
                                    SaveOpenRecords("open_data.json");
                                }
                                IsUnlocked = true;
                                ClearPassword();
                            }
                        });
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
                    break;
            }
        }

        public void AddNewRecord()
        {
            var encrypted = EncryptedRecordDataModel<object>.Create(EncryptedDictionary, Display, Key ?? string.Empty, Secret ?? string.Empty, null);
            Records.Add(encrypted);
            if (EncryptedDictionary.KeyPassword != null)
            {
                EncryptedDictionary.EncryptAll();
                EncryptedDictionary.Save("secrets.json");
                OpenRecords.Add(new OpenRecordDataModel<object>() { Display = Display, PairingKey = encrypted.PairingKey });
                SaveOpenRecords("open_data.json");
            }

            Display = Key = Secret = null;
            foreach (var value in new string[] { nameof(Display), nameof(Key), nameof(Secret) })
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
                    OpenRecords = JsonConvert.DeserializeObject<List<OpenRecordDataModel<object>>>(text);
                }
            }
            if (OpenRecords == null) { OpenRecords = new List<OpenRecordDataModel<object>>(); }
        }
    }
}
