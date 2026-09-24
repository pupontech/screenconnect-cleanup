using ScreenConnectCleanup.Gui.ViewModels;
using System.Windows;

namespace ScreenConnectCleanup.Gui;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainWindowViewModel();
    }
}
