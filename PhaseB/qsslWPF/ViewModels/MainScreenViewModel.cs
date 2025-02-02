using Microsoft.Win32;
using qsslSdk;
using qsslWPF.View;
using qsslWPF.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace qsslWPF.ViewModels
{
    public class MainScreenViewModel : ViewModelBase
    {
        public event Action RequestClose;

        private SDK sdk;
        private string _keyPath;

        public string KeyPath
        {
            get
            {
                return _keyPath;
            }
            set
            {
                _keyPath = value;
                OnPropertyChanged(nameof(KeyPath));
            }
        }

        public ICommand OpenKeyCommand { get; }
        public ICommand LoadKeyCommand { get; }
        

        public MainScreenViewModel()
        {
            OpenKeyCommand = new ViewModelCommand(ExecuteOpenKeyCommand);
            LoadKeyCommand = new ViewModelCommand(ExecuteLoadKeyCommand, CanExecuteLoadKeyCommand);
            
            // Access the global SDK instance
            sdk = ((App)Application.Current).sdk;
        }

        private bool CanExecuteLoadKeyCommand(object obj)
        {
            bool validData;
            if (string.IsNullOrWhiteSpace(KeyPath))
                validData = false;
            else
                validData = true;

            return validData;
        }

        private void ExecuteLoadKeyCommand(object obj)
        {
            //sending the path to SDK
            sdk.SendFilePath(KeyPath);
            System.Diagnostics.Debug.WriteLine("Key path sent to SDK!");

            //open login window
            var loginView = new LoginView();
            loginView.Show();

            // Request the view to close
            Application.Current.Dispatcher.BeginInvoke(new Action(() => RequestClose?.Invoke()));
        }

        private void ExecuteOpenKeyCommand(object obj)
        {
            // Create an instance of OpenFileDialog
            OpenFileDialog openFileDialog = new OpenFileDialog();

            // Set filters for file types (optional)
            openFileDialog.Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*";

            // Show the OpenFileDialog
            if (openFileDialog.ShowDialog() == true)
            {
                // Display the selected file path in the TextBox
                KeyPath = openFileDialog.FileName;
            }
        }
    }
}
