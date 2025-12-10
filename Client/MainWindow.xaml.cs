using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace Client
{
    public partial class MainWindow : Window
    {
        private TraceEventSession _session;
        private ETWTraceEventSource _source;
        private readonly ObservableCollection<TraceItem> _items = new ObservableCollection<TraceItem>();
        private ICollectionView _view;

        public MainWindow()
        {
            InitializeComponent();

            TraceGrid.ItemsSource = _items;

            _view = CollectionViewSource.GetDefaultView(_items);
            _view.Filter = ApplyFilter;

            Loaded += MainWindow_Loaded;
            Closing += MainWindow_Closing;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            Task.Run(() => StartListening());
        }

        private void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            try { _session?.Dispose(); } catch { }
            try { _source?.Dispose(); } catch { }
        }

        private bool ApplyFilter(object obj)
        {
            if (obj is TraceItem item)
            {
                // Hide LOG type when checkbox is unchecked
                if (ShowLogsCheckBox != null && ShowLogsCheckBox.IsChecked == false && string.Equals(item.Type, "LOG", StringComparison.OrdinalIgnoreCase))
                    return false;

                var filterText = FilterTextBox?.Text ?? string.Empty;
                if (string.IsNullOrWhiteSpace(filterText))
                    return true;

                var ft = filterText.Trim();
                var type = item.Type ?? string.Empty;
                var message = item.Message ?? string.Empty;

                return type.IndexOf(ft, StringComparison.OrdinalIgnoreCase) >= 0
                    || message.IndexOf(ft, StringComparison.OrdinalIgnoreCase) >= 0;
            }
            return true;
        }

        private void FilterTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            // Refresh the view to re-apply the filter on text change
            _view?.Refresh();
        }

        private void ShowLogsCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            // Show LOG entries when checkbox is checked
            _view?.Refresh();
        }

        private void ShowLogsCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            // Hide LOG entries when checkbox is unchecked
            _view?.Refresh();
        }

        private void StartListening()
        {
            try
            {
                using (var session = new TraceEventSession("UnkoverClientSession"))
                {
                    _session = session;
                    _session.StopOnDispose = true;

                    session.EnableProvider(new Guid("95bc72d9-99bc-7317-12bc-dac4e219200c"));

                    using (var source = new ETWTraceEventSource("UnkoverClientSession", TraceEventSourceType.Session))
                    {
                        _source = source;

                        source.Dynamic.All += (TraceEvent data) =>
                        {
                            try
                            {
                                string type = null;
                                string message = null;
                                try { type = data.PayloadByName("Type") as string; } catch { }
                                try { message = data.PayloadByName("Message") as string; } catch { }

                                if (string.IsNullOrEmpty(type)) type = data.ProviderName ?? "unKover";
                                if (message == null) message = data.FormattedMessage ?? string.Empty;

                                var timestamp = data.TimeStamp.ToLocalTime();

                                Dispatcher.Invoke(() =>
                                {
                                    _items.Insert(0, new TraceItem { Type = type, Message = message, Timestamp = timestamp });
                                    //if (_items.Count > 2000) _items.RemoveAt(_items.Count - 1);
                                });
                            }
                            catch (Exception ex)
                            {
                                Dispatcher.Invoke(() => MessageBox.Show(this, ex.Message));
                            }
                        };

                        source.Process();
                    }
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => MessageBox.Show(this, "Failed to start ETW session: " + ex.Message));
            }
        }
    }

    public class TraceItem
    {
        public string Type { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
