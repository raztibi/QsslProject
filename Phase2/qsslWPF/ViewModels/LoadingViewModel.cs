using qsslSdk;
using qsslWPF.View;
using qsslWPF.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace qsslWPF.ViewModels
{
    class LoadingViewModel : ViewModelBase
    {
        public event Action RequestClose;
        private SDK sdk;

        public LoadingViewModel()
        {
            sdk = ((App)Application.Current).sdk;
            sdk.LoginResultEvent += Sdk_LoginResultEventHandler;
        }

        private void Sdk_LoginResultEventHandler(bool obj)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (obj)
                {
                    var successView = new SuccessView();
                    successView.Show();
                }
                else
                {

                    var loginViewModel = new LoginViewModel("Login Operation failed");
                    var loginView = new LoginView { DataContext = loginViewModel };
                    loginViewModel.RequestClose += () => loginView.Close();
                    loginView.Show();
                }

                sdk.LoginResultEvent -= Sdk_LoginResultEventHandler;
                // Request the view to close
                RequestClose?.Invoke();
            });
        }
    }
}
