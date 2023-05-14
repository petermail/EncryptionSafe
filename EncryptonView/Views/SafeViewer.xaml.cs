using EncryptionSafe.Encryption;
using EncryptionView.Models;
using EncryptonView.Models;
using Microsoft.Win32;
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
            ViewModel.DoActiveStateAction(PasswordBox1.SecurePassword, ViewModel.FilePassword);
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

        private void ButtonGetFile_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.LoadFilePassword();
        }

        private void MenuItemOpen_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.OpenFile();
        }

        private void DataGrid_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Delete)
            {
                var selected = ((DataGrid)sender).SelectedCells.FirstOrDefault().Item as EncryptedRecordDataModel<object>;
                if (selected != null)
                {
                    ViewModel.DeleteItem(selected);
                }
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
        private bool _isOnlyDecryptedData = true;
        public bool IsOnlyDecryptedData { get { return _isOnlyDecryptedData; } 
            set { 
                _isOnlyDecryptedData = value; 
                if (value)
                {
                    FilterDecryptedRecords();
                } else
                {
                    ClearFilter();
                }
            } 
        }
        private string _filePassword;
        public string FilePassword { get { return _filePassword; }
            set
            {
                _filePassword = value;
                PropertyChanged(this, new PropertyChangedEventArgs(nameof(FilePassword)));
            }
        }
        public ObservableCollection<EncryptedRecordDataModel<object>> Records { get; set; }
        public List<OpenRecordDataModel<object>> OpenRecords { get; set; }
        public string Display { get; set; }
        public string Key { get; set; }
        public string Secret { get; set; }
        private List<EncryptedRecordDataModel<object>> _hiddenRecords = new List<EncryptedRecordDataModel<object>>();

        public Action ClearPassword { get; set; }

        public EncryptedDictionary EncryptedDictionary { get; set; }

        private const string ACTION_DECRYPT = "Decrypt";
        private const string ACTION_STOP = "Stop";
        private const string ACTION_ENCRYPT = "Encrypt";
        private const string ACTION_WAIT = "Initialization";

        private Task _encryptionTask;
        private int _taskId = 0;

        private string _filenameOfFull = null;
        
        public SafeViewerViewModel()
        {
            OpenRecords = new List<OpenRecordDataModel<object>>();
            Records = new ObservableCollection<EncryptedRecordDataModel<object>>();
            ActionButtonText = ACTION_DECRYPT;
            var cmd = Environment.GetCommandLineArgs();
            if (cmd.Length > 1) { _filenameOfFull = cmd[1]; }
            LoadFull();
            //EncryptedDictionary = EncryptedDictionary.LoadOrCreate("secrets.json").Result;
            if (EncryptedDictionary.EncryptionService.IsInitializationRunning)
            {
                ActionButtonText = ACTION_WAIT;
                IsActionEnabled = false;
                EncryptedDictionary.EncryptionService.InitializationCallback = () =>
                {
                    ActionButtonText = ACTION_DECRYPT;
                    IsActionEnabled = true;
                    Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
                    //EncryptedDictionary.Save("secrets.json");
                    SaveFull(true);
                };
            } else
            {
                /*Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
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
                }*/
                if (IsOnlyDecryptedData)
                {
                    FilterDecryptedRecords();
                }
            }
        }

        public void FilterDecryptedRecords()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                int hiddenRecordCount = _hiddenRecords.Count;
                for (int i = Records.Count - 1; i >= 0; --i)
                {
                    var record = Records[i];
                    if (record.EncryptedState == EncryptedType.FullyEncrypted || record.IsDeleted == true)
                    {
                        _hiddenRecords.Add(record);
                        Records.RemoveAt(i);
                    }
                }
                for (int i = hiddenRecordCount - 1; i >= 0; --i)
                {
                    if (_hiddenRecords[i].EncryptedState != EncryptedType.FullyEncrypted || _hiddenRecords[i].IsDeleted == true)
                    {
                        Records.Add(_hiddenRecords[i]);
                        _hiddenRecords.RemoveAt(i);
                    }
                }
            });
        }
        public void ClearFilter()
        {
            foreach (var item in _hiddenRecords)
            {
                Records.Add(item);
            }
            _hiddenRecords.Clear();
        }

        public void DoActiveStateAction(SecureString password, string filePassword)
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
                            if (!string.IsNullOrWhiteSpace(filePassword))
                            {
                                if (System.IO.File.Exists(filePassword))
                                {
                                    pwd = EncryptionService.AppendHashFile(pwd, filePassword);
                                } else { MessageBox.Show("File for password hash doesn't exist."); }
                            }
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
                                foreach (var record in _hiddenRecords)
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
                            if (IsOnlyDecryptedData)
                            {
                                FilterDecryptedRecords();
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
                    foreach (var record in _hiddenRecords)
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
                OpenRecords.Add(new OpenRecordDataModel<object>() { Display = Display, PairingKey = encrypted.PairingKey });
                SaveFull();
            }

            Display = Key = Secret = null;
            foreach (var value in new string[] { nameof(Display), nameof(Key), nameof(Secret) })
            {
                PropertyChanged(this, new PropertyChangedEventArgs(value));
            }
        }

        public void SaveFull(bool isFirstSave = false)
        {
            if (_filenameOfFull != null)
            {
                var fullModel = new DictionaryAndDataModel<object>() { EncryptedDictionary = EncryptedDictionary, OpenRecords = OpenRecords };
                if (isFirstSave)
                {
                    fullModel.SaveWithoutEncrypt(_filenameOfFull);
                }
                else
                {
                    fullModel.Save(_filenameOfFull);
                }
            } else
            {
                if (!isFirstSave)
                {
                    EncryptedDictionary.EncryptAll();
                }
                EncryptedDictionary.Save("secrets.json");
                SaveOpenRecords("open_data.json");
            }
        }
        public void LoadFull()
        {
            if (_filenameOfFull != null)
            {
                var fullModel = new DictionaryAndDataModel<object>();
                fullModel.Load(_filenameOfFull);
                EncryptedDictionary = fullModel.EncryptedDictionary;
                OpenRecords = fullModel.OpenRecords;
                if (EncryptedDictionary == null)
                {
                    EncryptedDictionary = new EncryptedDictionary();
                    EncryptedDictionary.EncryptionService = new EncryptionService();
                    EncryptedDictionary.EncryptionService.IsInitializationRunning = true;
                    Task.Run(async () => await EncryptedDictionary.InitializeAsync());
                }
                else
                {
                    Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
                }
                foreach (var value in EncryptedDictionary.Dictionary)
                {
                    var keySecret = value.Key.Split('_');
                    if (keySecret.Length > 1 && keySecret[1] == "key")
                    {
                        Records.Add(new EncryptedRecordDataModel<object>(EncryptedDictionary, null, null, keySecret[0]));
                    }
                }
                foreach (var openRecord in OpenRecords)
                {
                    var encrypted = Records.FirstOrDefault(x => x.PairingKey == openRecord.PairingKey);
                    if (encrypted != null)
                    {
                        encrypted.OpenData = openRecord.OpenData;
                        encrypted.Display = openRecord.Display;
                    }
                }
            } else
            {
                EncryptedDictionary = EncryptedDictionary.Load("secrets.json");
                if (EncryptedDictionary == null)
                {
                    EncryptedDictionary = new EncryptedDictionary();
                    EncryptedDictionary.EncryptionService = new EncryptionService();
                    EncryptedDictionary.EncryptionService.IsInitializationRunning = true;
                    Task.Run(async () => await EncryptedDictionary.InitializeAsync());
                } else
                {
                    foreach (var value in EncryptedDictionary.Dictionary)
                    {
                        var keySecret = value.Key.Split('_');
                        if (keySecret.Length > 1 && keySecret[1] == "key")
                        {
                            Records.Add(new EncryptedRecordDataModel<object>(EncryptedDictionary, null, null, keySecret[0]));
                        }
                    }
                    LoadOpenRecords("open_data.json");
                    foreach (var openRecord in OpenRecords)
                    {
                        var encrypted = Records.FirstOrDefault(x => x.PairingKey == openRecord.PairingKey);
                        if (encrypted != null)
                        {
                            encrypted.OpenData = openRecord.OpenData;
                            encrypted.Display = openRecord.Display;
                        }
                    }
                    Iterations = EncryptedDictionary.EncryptionService.PasswordIterations;
                }
            }
        }
        private void SaveOpenRecords(string filename)
        {
            var text = JsonConvert.SerializeObject(OpenRecords);
            using (var sw = new System.IO.StreamWriter(filename))
            {
                sw.WriteLine(text);
                sw.Close();
            }
        }
        private void LoadOpenRecords(string filename)
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

        public void DeleteItem(EncryptedRecordDataModel<object> item)
        {
            if (MessageBox.Show(string.Format("Ary you sure you want to delete selected item [{0}]?", item.Display), 
                "Delete item", MessageBoxButton.YesNoCancel, MessageBoxImage.Question)
                == MessageBoxResult.Yes)
            {
                item.IsDeleted = true;
                FilterDecryptedRecords();
            }
        }

        public void OpenFile()
        {
            var ofd = new OpenFileDialog();
            ofd.Filter = "Json (*.json)|*.json|All files (*.*)|*.*";
            if (ofd.ShowDialog() ?? false)
            {
                _filenameOfFull = ofd.FileName;
                LoadFull(); // We can load only data encrypted into one file
                // Open_data, secret - format of two files is not supported, it would be problem when savings
            }
        }

        public void LoadFilePassword()
        {
            var ofd = new OpenFileDialog();
            ofd.Filter = "All files (*.*)|*.*";
            if (ofd.ShowDialog() ?? false)
            {
                FilePassword = ofd.FileName;
            }
        }
    }
}
