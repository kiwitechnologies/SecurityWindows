// **************************************************************
// *
// * Written By: Nishant Sukhwal
// * Copyright © 2016 kiwitech. All rights reserved.
// **************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Graphics.Display;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.UI.ViewManagement;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Imaging;
using Windows.UI.Xaml.Navigation;
using Windows.UI.Popups;
using Windows.Security.Cryptography.Core;
using Windows.Security.Cryptography;
using TSGSecurity;
using Example.Common;
// The Basic Page item template is documented at http://go.microsoft.com/fwlink/?LinkID=390556

namespace Example
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class EncryptionPage : Page
    {
        private NavigationHelper navigationHelper;
        private ObservableDictionary defaultViewModel = new ObservableDictionary();
        byte[] secureKey = Encoding.UTF8.GetBytes("xcrtNMQdd0FloLyw");
        string strAES256Key = "bbC2H19lkVbQDfakxcrtNMQdd0FloLyw";
        string strAES128Key = "xcrtNMQdd0FloLyw";
        string strIVector = "gqLOHUioQ0QjhuvI";
        SecurityType securityType = SecurityType.DEFAULT;

        public EncryptionPage()
        {
            this.InitializeComponent();

            this.navigationHelper = new NavigationHelper(this);
            this.navigationHelper.LoadState += this.NavigationHelper_LoadState;
            this.navigationHelper.SaveState += this.NavigationHelper_SaveState;
        }

        /// <summary>
        /// Gets the <see cref="NavigationHelper"/> associated with this <see cref="Page"/>.
        /// </summary>
        public NavigationHelper NavigationHelper
        {
            get { return this.navigationHelper; }
        }

        /// <summary>
        /// Gets the view model for this <see cref="Page"/>.
        /// This can be changed to a strongly typed view model.
        /// </summary>
        public ObservableDictionary DefaultViewModel
        {
            get { return this.defaultViewModel; }
        }

        /// <summary>
        /// Populates the page with content passed during navigation.  Any saved state is also
        /// provided when recreating a page from a prior session.
        /// </summary>
        /// <param name="sender">
        /// The source of the event; typically <see cref="NavigationHelper"/>
        /// </param>
        /// <param name="e">Event data that provides both the navigation parameter passed to
        /// <see cref="Frame.Navigate(Type, Object)"/> when this page was initially requested and
        /// a dictionary of state preserved by this page during an earlier
        /// session.  The state will be null the first time a page is visited.</param>
        private void NavigationHelper_LoadState(object sender, LoadStateEventArgs e)
        {
        }

        /// <summary>
        /// Preserves state associated with this page in case the application is suspended or the
        /// page is discarded from the navigation cache.  Values must conform to the serialization
        /// requirements of <see cref="SuspensionManager.SessionState"/>.
        /// </summary>
        /// <param name="sender">The source of the event; typically <see cref="NavigationHelper"/></param>
        /// <param name="e">Event data that provides an empty dictionary to be populated with
        /// serializable state.</param>
        private void NavigationHelper_SaveState(object sender, SaveStateEventArgs e)
        {
        }

        #region NavigationHelper registration

        /// <summary>
        /// The methods provided in this section are simply used to allow
        /// NavigationHelper to respond to the page's navigation methods.
        /// <para>
        /// Page specific logic should be placed in event handlers for the  
        /// <see cref="NavigationHelper.LoadState"/>
        /// and <see cref="NavigationHelper.SaveState"/>.
        /// The navigation parameter is available in the LoadState method 
        /// in addition to page state preserved during an earlier session.
        /// </para>
        /// </summary>
        /// <param name="e">Provides data for navigation methods and event
        /// handlers that cannot cancel the navigation request.</param>
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            this.navigationHelper.OnNavigatedTo(e);
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            this.navigationHelper.OnNavigatedFrom(e);
        }

        #endregion

        /// <summary>
        /// This is the click event to encrypt text in AES-128 Encryption, AES-256 Encryption and MD5-Hashing.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (securityType == SecurityType.DEFAULT)
            {
                if (lstOptions.Visibility == Visibility.Collapsed)
                {
                    lstOptions.Visibility = Visibility.Visible;
                }
                //await new MessageDialog("Please select encryption option.").ShowAsync();
                return;
            }
            txtDecryptResult.Text = string.Empty;
            if (!string.IsNullOrEmpty(txtMessage.Text.Trim()))
            {
                if (securityType == SecurityType.AES128)
                {
                    object oResult = TSGSecurityManager.Encrypt(txtMessage.Text, SecurityType.AES128, strAES128Key, strIVector);
                    await DisplayIncryptedResultForString(oResult);

                    btnDecrypt.Visibility = Visibility.Visible;
                }
                else if (securityType == SecurityType.AES256)
                {
                    object oResult = TSGSecurityManager.Encrypt(txtMessage.Text, SecurityType.AES256, strAES256Key, strIVector);
                    await DisplayIncryptedResultForString(oResult);
                    btnDecrypt.Visibility = Visibility.Visible;
                }
                else if (securityType == SecurityType.MD5)
                {
                    object oResult = TSGSecurityManager.Encrypt(txtMessage.Text, SecurityType.MD5, string.Empty, string.Empty);
                    await DisplayIncryptedResultForString(oResult);
                    btnDecrypt.Visibility = Visibility.Collapsed;
                }
                grdResult.Visibility = Visibility.Visible;
            }
            else
            {
                await new MessageDialog("Please fill text.").ShowAsync();
            }
        }

        private async Task DisplayIncryptedResultForString(object oResult)
        {
            if (oResult.GetType() == typeof(Tuple<bool, string>))
            {
                Tuple<bool, string> res = oResult as Tuple<bool, string>;
                bool isValid = res.Item1;
                string strResult = res.Item2;
                if (isValid)
                {
                    if (!string.IsNullOrEmpty(strResult))
                    {
                        txtEncryptResult.Text = strResult;
                    }
                }
                else
                {
                    await new MessageDialog("Unable to encrypt.").ShowAsync();
                }
            }
        }

        /// <summary>
        /// This is the click event to decrypt text in AES-128 Encryption, AES-256 Encryption and MD5-Hashing.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(txtEncryptResult.Text.Trim()))
            {
                if (securityType == SecurityType.AES128)
                {
                    object oResult = TSGSecurityManager.Decrypt(txtEncryptResult.Text, SecurityType.AES128, strAES128Key, strIVector);
                    await DisplayDecryptedResultForString(oResult);
                }
                else if (securityType == SecurityType.AES256)
                {
                    object oResult = TSGSecurityManager.Decrypt(txtEncryptResult.Text, SecurityType.AES256, strAES256Key, strIVector);
                    await DisplayDecryptedResultForString(oResult);
                }
                else if (securityType == SecurityType.MD5)
                {
                    object oResult = TSGSecurityManager.Encrypt(txtMessage.Text, SecurityType.MD5, string.Empty, string.Empty);
                    await DisplayDecryptedResultForString(oResult);
                }
            }
        }

        private async Task DisplayDecryptedResultForString(object oResult)
        {
            if (oResult.GetType() == typeof(Tuple<bool, string>))
            {
                Tuple<bool, string> res = oResult as Tuple<bool, string>;
                bool isValid = res.Item1;
                string strResult = res.Item2;
                if (isValid)
                {
                    if (!string.IsNullOrEmpty(strResult))
                    {
                        txtDecryptResult.Text = strResult;
                    }
                }
                else
                {
                    await new MessageDialog("Unable to decrypt.").ShowAsync();
                }
            }
        }

        /// <summary>
        /// This is the click event to encrypt image in AES-128 Encryption, AES-256 Encryption and MD5-Hashing.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void btnEncryptImage_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (securityType == SecurityType.DEFAULT)
                {
                    if (lstOptions.Visibility == Visibility.Collapsed)
                    {
                        lstOptions.Visibility = Visibility.Visible;
                    }
                    //await new MessageDialog("Please select encryption option.").ShowAsync();
                    return;
                }
                imgNew.Source = null;
                string strBase64 = string.Empty;
                BitmapImage bitmapImage = img.Source as BitmapImage;
                byte[] bytes = new byte[0];
                var sFile = await StorageFile.GetFileFromApplicationUriAsync(new Uri("ms-appx:///image.jpg", UriKind.RelativeOrAbsolute));
                bytes = await GetByteFromFile(sFile);

                if (securityType == SecurityType.AES128)
                {
                    object oResult = TSGSecurityManager.Encrypt(bytes, SecurityType.AES128, strAES128Key, strIVector);
                    await DisplayIncryptedResultForData(oResult);
                    btnDecryptImage.Visibility = Visibility.Visible;
                    grdResultImage.Visibility = Visibility.Visible;
                }
                else if (securityType == SecurityType.AES256)
                {
                    object oResult = TSGSecurityManager.Encrypt(bytes, SecurityType.AES256, strAES256Key, strIVector);
                    await DisplayIncryptedResultForData(oResult);
                    btnDecryptImage.Visibility = Visibility.Visible;
                    grdResultImage.Visibility = Visibility.Visible;
                }
                else if (securityType == SecurityType.MD5)
                {
                    object oResult = TSGSecurityManager.Encrypt(bytes, SecurityType.MD5, string.Empty, string.Empty);
                    await DisplayIncryptedResultForData(oResult);
                    btnDecryptImage.Visibility = Visibility.Collapsed;
                    grdResultImage.Visibility = Visibility.Visible;
                }
            }
            catch (Exception ex)
            {

            }
        }

        private async Task DisplayIncryptedResultForData(object oResult)
        {
            if (oResult.GetType() == typeof(Tuple<bool, byte[]>))
            {
                Tuple<bool, byte[]> res = oResult as Tuple<bool, byte[]>;
                bool isValid = res.Item1;
                byte[] bData = res.Item2;
                if (isValid)
                {
                    txtEncryptImageResult.Text = Convert.ToBase64String(bData);
                }
                else
                {
                    await new MessageDialog("Unable to encrypt.").ShowAsync();
                }
            }
        }

        /// <summary>
        /// This is the click event to decrypt text in AES-128 Encryption, AES-256 Encryption and MD5-Hashing.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void btnDecryptImage_Click(object sender, RoutedEventArgs e)
        {
            if (securityType == SecurityType.AES128)
            {
                object oResult = TSGSecurityManager.Decrypt(Convert.FromBase64String(txtEncryptImageResult.Text), SecurityType.AES128, strAES128Key, strIVector);
                await DisplayDecryptedResultForData(oResult);

            }
            else if (securityType == SecurityType.AES256)
            {
                object oResult = TSGSecurityManager.Decrypt(Convert.FromBase64String(txtEncryptImageResult.Text), SecurityType.AES128, strAES256Key, strIVector);
                await DisplayDecryptedResultForData(oResult);
            }
            else if (securityType == SecurityType.MD5)
            {
                string strBase64 = string.Empty;
                byte[] bytes = new byte[0];
                var sFile = await StorageFile.GetFileFromApplicationUriAsync(new Uri("ms-appx:///image.jpg", UriKind.RelativeOrAbsolute));
                bytes = await GetByteFromFile(sFile);
                strBase64 = Convert.ToBase64String(bytes, 0, bytes.Length);
                object oResult = TSGSecurityManager.Encrypt(strBase64, SecurityType.MD5, string.Empty, string.Empty);
                await DisplayDecryptedResultForData(oResult);
            }
        }

        private async Task DisplayDecryptedResultForData(object oResult)
        {
            if (oResult.GetType() == typeof(Tuple<bool, byte[]>))
            {
                Tuple<bool, byte[]> res = oResult as Tuple<bool, byte[]>;
                bool isValid = res.Item1;
                byte[] bData = res.Item2;
                if (isValid)
                {
                    if (bData != null)
                    {
                        using (InMemoryRandomAccessStream ms = new InMemoryRandomAccessStream())
                        {
                            ms.Seek(0);
                            using (DataWriter writer = new DataWriter(ms.GetOutputStreamAt(0)))
                            {
                                writer.WriteBytes((byte[])bData);
                                writer.StoreAsync().GetResults();
                            }
                            var image = new BitmapImage();
                            image.SetSource(ms);
                            imgNew.Source = image;
                        }
                    }
                }
                else
                {
                    await new MessageDialog("Unable to decrypt.").ShowAsync();
                }
            }
        }

        /// <summary>
        /// The method is to convert image file into bytes.
        /// </summary>
        /// <param name="storageFile"></param>
        /// <returns></returns>
        private static async Task<byte[]> GetByteFromFile(StorageFile storageFile)
        {
            byte[] byteData = null;
            try
            {
                var fileSize = await storageFile.GetBasicPropertiesAsync();
                if (storageFile != null && fileSize.Size > 0)
                {
                    using (IRandomAccessStream fileStream = await storageFile.OpenAsync(FileAccessMode.Read))
                    {
                        var reader = new DataReader(fileStream.GetInputStreamAt(0));
                        await reader.LoadAsync((uint)fileStream.Size);
                        byteData = new byte[fileStream.Size];
                        reader.ReadBytes(byteData);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("EncryptionPage---------GetByteFromFile" + ex.Message);
            }
            return byteData;
        }

        /// <summary>
        /// This is the click event to reset everything.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnClear_Click(object sender, RoutedEventArgs e)
        {
            txtMessage.Text = string.Empty;
            Reset();
        }

        /// <summary>
        /// This is the method to reset all fields.
        /// </summary>
        private void Reset()
        {

            txtEncryptResult.Text = string.Empty;
            txtDecryptResult.Text = string.Empty;
            txtEncryptImageResult.Text = string.Empty;
            imgNew.Source = null;
            grdResult.Visibility = Visibility.Collapsed;
            lstOptions.Visibility = Visibility.Collapsed;
            grdResultImage.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        /// This is the click event to open encryption options.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnMenu_Click(object sender, RoutedEventArgs e)
        {
            if (lstOptions.Visibility == Visibility.Collapsed)
            {
                lstOptions.Visibility = Visibility.Visible;
            }
            else
            {
                lstOptions.Visibility = Visibility.Collapsed;
            }
        }

        /// <summary>
        /// Selection changed event fires when user select any encryption option.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void lstOptions_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ListBox lBox = (sender as ListBox);
            ListBoxItem lbi = lBox.SelectedItem as ListBoxItem;
            if (lbi != null)
            {
                lstOptions.Visibility = Visibility.Collapsed;
                Reset();
                if (lbi.Content.ToString() == "AES-128 Encryption")
                {
                    securityType = SecurityType.AES128;
                    secureKey = Encoding.UTF8.GetBytes(strAES128Key);
                    btnEncrypt.Content = "AES-128 Encryption";
                    btnEncryptImage.Content = "AES-128 Encryption";
                }
                else if (lbi.Content.ToString() == "AES-256 Encryption")
                {
                    securityType = SecurityType.AES256;
                    secureKey = Encoding.UTF8.GetBytes(strAES256Key);
                    btnEncrypt.Content = "AES-256 Encryption";
                    btnEncryptImage.Content = "AES-256 Encryption";
                }
                else if (lbi.Content.ToString() == "Create MD5")
                {
                    securityType = SecurityType.MD5;
                    btnEncrypt.Content = "Create MD5";
                    btnEncryptImage.Content = "Create MD5";
                }
            }
            lBox.SelectedIndex = -1;
        }

    }
}
