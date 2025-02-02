using qsslWPF.View;
using qsslWPF.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace qsslWPF.ViewModels
{
    class SuccessViewModel : ViewModelBase
    {
        public event Action RequestClose;
        public ICommand ReturnCommand { get; }
        public SuccessViewModel()
        {
            ReturnCommand = new ViewModelCommand(ExecuteReturn);
        }

        private void ExecuteReturn(object obj)
        {
            var loginView = new LoginView();
            loginView.Show();
            RequestClose?.Invoke();
        }

    }
}
