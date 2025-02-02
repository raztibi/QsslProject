using qsslWPF.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace qsslWPF.View
{
    /// <summary>
    /// Interaction logic for LoadingB.xaml
    /// </summary>
    public partial class LoadingView : Window
    {
        public LoadingView()
        {
            InitializeComponent();
            StartLoading();
            
            if (DataContext is LoadingViewModel viewModel)
            {
                viewModel.RequestClose += () =>
                {
                    this.Close();
                };
            }
        }

        private async void StartLoading()
        {
            // Simulate loading process
            for (int i = 0; i <= 100; i++)
            {
                loadingBar.Value = i; // Update the ProgressBar value
                await Task.Delay(50); // Simulate delay (50ms)
            }
        }

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void btnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void btnCloseWindow_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}
