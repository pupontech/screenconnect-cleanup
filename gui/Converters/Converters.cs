using ScreenConnectCleanup.Gui.Models;
using ScreenConnectCleanup.Gui.Services;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace ScreenConnectCleanup.Gui.Converters;

/// <summary>
/// Converts status string to visibility.
/// </summary>
public class StatusToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string status)
        {
            var showFor = parameter as string ?? "Completed,Warning,Incomplete";
            var statuses = showFor.Split(',');
            return statuses.Contains(status) ? Visibility.Visible : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts status string to a color brush.
/// </summary>
public class StatusToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string status)
        {
            return status switch
            {
                "Completed" => System.Windows.Media.Brushes.Green,
                "Warning" => System.Windows.Media.Brushes.Orange,
                "Failed" => System.Windows.Media.Brushes.Red,
                "Incomplete" => System.Windows.Media.Brushes.Gray,
                "Running" => System.Windows.Media.Brushes.Blue,
                "Pending" => System.Windows.Media.Brushes.Gray,
                "Skipped" => System.Windows.Media.Brushes.DarkGray,
                "NeedsAction" => System.Windows.Media.Brushes.OrangeRed,
                "RebootPending" => System.Windows.Media.Brushes.Purple,
                _ => System.Windows.Media.Brushes.Gray
            };
        }
        return System.Windows.Media.Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts boolean to collapsed/visible.
/// </summary>
public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b)
        {
            return b ? Visibility.Visible : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is Visibility v)
        {
            return v == Visibility.Visible;
        }
        return false;
    }
}

/// <summary>
/// Converts review decision to display text.
/// </summary>
public class DecisionToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ReviewDecision decision)
        {
            return decision switch
            {
                ReviewDecision.ApproveRemoval => "Approved for removal",
                ReviewDecision.DeclineRemoval => "Declined removal",
                _ => "No decision made"
            };
        }
        return "No decision made";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts DateTime to relative time string.
/// </summary>
public class DateTimeToRelativeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is DateTime dt)
        {
            var span = DateTime.UtcNow - dt;
            if (span.TotalMinutes < 1)
                return "Just now";
            if (span.TotalMinutes < 60)
                return $"{(int)span.TotalMinutes}m ago";
            if (span.TotalHours < 24)
                return $"{(int)span.TotalHours}h ago";
            return $"{(int)span.TotalDays}d ago";
        }
        return "Unknown";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
