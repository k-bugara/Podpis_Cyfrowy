using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
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
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Text.RegularExpressions;
using System.Numerics;
using System.Threading;
using System.Security.Cryptography;

namespace Digital_Signature
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        #region Consts
        const int DIGITS_DIFFERENCE = 20; // p ~ q
        BigInteger MIN = new BigInteger(10000000000) * new BigInteger(10000000000); // minimalna wartość z p * q
        #endregion

        #region Properties
        public string FileName { get; set; }
        public byte[] Message { get; set; }
        public string Signature { get; set; }
        #endregion

        #region Constructor
        public MainWindow()
        {
            InitializeComponent();
        }
        #endregion

        #region Event Handlers
        #region btnFile_Click. Otwórz OpenFileDialog, ustaw lokalizację pliku i załaduj plik w tablicy bajtów.
        private void btnFile_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
            dlg.ShowDialog();

            FileName = dlg.FileName;
            FileName = FileName;
            

            if (FileName == "")
                System.Windows.MessageBox.Show("Error: nie można załadować pliku.");
            else
            {
                // wytnij nazwe pliku
                if (FileName.Length > (int)lblFileName.Width - 20)
                    lblFileName.Content = "..." + FileName.Substring(FileName.Length - (int) lblFileName.Width - 20);
                else
                    lblFileName.Content = FileName;

                // zaladuj plik jako tablice bajtow
                byte[] _Message = new byte[File.ReadAllBytes(FileName).Length];
                _Message = File.ReadAllBytes(FileName);

                this.Message = new byte[_Message.Length];
                this.Message = _Message;
                                
                // tbSource.Text = BitConverter.ToString(arr);
                tbMessage.Text = string.Join(" ", _Message.Select(b => b.ToString()));
            }
        }
        #endregion 
        #region private void btnSignFile_Click(object sender, RoutedEventArgs e). Zaladuj podpis cyfrowy z pliku.
        private void btnSignFile_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
            dlg.ShowDialog();

            Signature = dlg.FileName;


            if (Signature == "")
                System.Windows.MessageBox.Show("Error: nie można załadować pliku.");
            else
            {
                // wytnij nazwe pliku
                if (Signature.Length > (int)lblSignFileName.Width - 20)
                    lblSignFileName.Content = "..." + Signature.Substring(Signature.Length - (int)lblSignFileName.Width - 20);
                else
                    lblSignFileName.Content = Signature;

                // zaladuj plik jako ciag
                Signature = File.ReadAllText(Signature);

                tbDigitalSignature.Text = Signature;
            }
        }
        #endregion

        #region btnSign_Click. Algorytm podpisywania, który po otrzymaniu wiadomości i klucza prywatnego tworzy podpis.
        private void btnSign_Click(object sender, RoutedEventArgs e)
        {
            if ((FileName == null) || (FileName == ""))
            {
                MessageBox.Show("Error: wybierz plik");
            }
            else if ((Message == null) || (Message.Length == 0))
            {
                MessageBox.Show("Error: pusty plik");
                return;
            }
            else
            {
                BigInteger p, q, eps, d; // sekretny klucz
                if (IsSecretKeyValid(out p, out q, out eps, out d))
                {
                    // modulo
                    BigInteger r;
                    r = p * q;
                    tbR.Text = r.ToString();

                    RSA RSA = new RSA(p, q, eps, d, r);
                    SHA_1 SHA1 = new SHA_1();

                    byte[] SHAHash = new byte[20];
                    SHAHash = SHA1.GetHash(Message).Value;

                    // Wartości BigInteger są reprezentowane w kolejności bajtów
                    Array.Reverse(SHAHash);

                    // upewnij się, że wartość dodatnia nie jest niepoprawnie utworzona jako wartość ujemna 
                    // przez dodanie bajtu, którego wartość wynosi zero na końcu tablicy
                    byte[] temp = new byte[SHAHash.Length];
                    Array.Copy(SHAHash, temp, SHAHash.Length);
                    SHAHash = new byte[temp.Length + 1];
                    Array.Copy(temp, SHAHash, temp.Length);

                    // konwersja tablicy skrótu na BigInteger
                    BigInteger BI_Hash = new BigInteger(SHAHash);

                    if (BI_Hash > r)
                    {
                        MessageBox.Show("Error: Hash jest wiekszy niz R.");
                        return;
                    }
                    
                    // decimal representation of hash
                    tbHashDecimal.Text = BI_Hash.ToString();

                    //dziesiętna reprezentacja hash'a
                    string hexHash = BI_Hash.ToString("X");
                    if (hexHash[0] == '0')
                    {
                        hexHash = hexHash.Substring(1);
                    }
                    tbHashHex.Text = hexHash;

                    // szyfruj hash
                    string signature = RSA.EncryptHash(BI_Hash).ToString();
                    
                    tbD.Text = RSA.D.ToString();
                    tbE.Text = RSA.E.ToString();

                    tbDigitalSignature.Text = signature;

                    // zapisz podpis do pliku 
                    File.WriteAllText(FileName.Substring(0, FileName.IndexOf('.')) + "_Podpis.txt", signature);
                }
            }
        }
        #endregion
        private void btnVerify_Click(object sender, RoutedEventArgs e)
        {
            if ((FileName == null) || (FileName == ""))
            {
                MessageBox.Show("Error: Wybierz plik.");
            } 
            else if ((Signature == null) || (Signature == ""))
            {
                MessageBox.Show("Error: Wybierz plik z podpisem.");
            }
            else
            {
                BigInteger eps, r; // klucz publiczny
                if (IsPublicKeyValid(out eps, out r))
                {
                    RSA RSA = new RSA(eps, r);
                    SHA_1 SHA1 = new SHA_1();

                    byte[] realHash = new byte[20];
                    realHash = SHA1.GetHash(Message).Value;

                    // Wartości BigInteger są reprezentowane w kolejności bajtów
                    Array.Reverse(realHash);

                    // upewnij się, że wartość dodatnia nie jest niepoprawnie utworzona jako wartość ujemna 
                    // przez dodanie bajtu, którego wartość wynosi zero na końcu tablicy
                    byte[] temp = new byte[realHash.Length];
                    Array.Copy(realHash, temp, realHash.Length);
                    realHash = new byte[temp.Length + 1];
                    Array.Copy(temp, realHash, temp.Length);

                    // dziesiętna reprezentacja hash'a
                    tbHashDecimal.Text = new BigInteger(realHash).ToString();

                    // szesnastkowa reprezentacja hash'a
                    string hexHash = new BigInteger(realHash).ToString("X");
                    if (hexHash[0] == '0')
                    {
                        hexHash = hexHash.Substring(1);
                    }
                    tbHashHex.Text = hexHash;

                    // konwersja podpisu do BigInteger
                    BigInteger BI_Hash = BigInteger.Parse(Signature);

                    // szyfruj skrót z pliku za pomocą klucza publicznego
                    byte[] checkedHash = new byte[20];
                    RSA Rsa = new RSA(eps, r);
                    checkedHash = Rsa.DecryptHash(BI_Hash).ToByteArray();

                    if (new BigInteger(realHash) > RSA.R)
                    {
                        MessageBox.Show("Error: Hash jest większy niż R.");
                        return;
                    }

                    // wypisuje zaszyfrowany skrót z pliku
                    tbCheckedHash.Text = new BigInteger(checkedHash).ToString();

                    if (new BigInteger(checkedHash) == new BigInteger(realHash))
                    {
                        MessageBox.Show("Podpis cyfrowy się zgadza. Plik jest autentyczny.");
                    }
                    else
                    {
                        MessageBox.Show("Podpis cyfrowy się nie zgadza!");
                    }

                }
            }
        }
        #region
        #endregion

        #region NumberValidationTextBox. Użytkownik może wprowadzić tylko cyfry
        private void NumberValidationTextBox(object sender, TextCompositionEventArgs e)
        {
            Regex regex = new Regex("[^0-9]+");
            e.Handled = regex.IsMatch(e.Text);
        }
        #endregion

        #endregion

        #region Methods
        #region private bool IsSecretKeyValid(out BigInteger p, out BigInteger q, out BigInteger eps). Sprawdź dane wejściowe.
        private bool IsSecretKeyValid(out BigInteger p, out BigInteger q, out BigInteger eps, out BigInteger d)
        {
            // inicializacja
            p = q = eps = d = 0;

            BigInteger.TryParse(tbE.Text, out eps);
            BigInteger.TryParse(tbD.Text, out d);

            if (!BigInteger.TryParse(tbP.Text, out p))
            {
                MessageBox.Show("Error: Nieprawidłowa wartość P.");
            }
            else if (!BigInteger.TryParse(tbQ.Text, out q))
            {
                MessageBox.Show("Error: Nieprawidłowa wartość Q.");
            }
            else if ((!(p.IsProbablyPrime())) || (!(q.IsProbablyPrime())))
            {
                MessageBox.Show("Error: Wartości P i Q muszą być liczbą pierwszą.");
            }
            else if (Math.Abs(p.ToString().Length - q.ToString().Length) > DIGITS_DIFFERENCE)
            {
                MessageBox.Show("Error: P i Q muszą być porównywalne.");
            }
            else if (p == q)
            {
                MessageBox.Show("Error: P i Q nie mogą być takie same.");
            }
            else if (eps >= p * q)
            {
                MessageBox.Show("Error: Eps musi być mniejszy niż P * Q.");
            }
            else if (d >= p * q)
            {
                MessageBox.Show("Error: D musi być mniejsze niż P * Q.");
            }
            else if ((eps == 0) && (d == 0))
            {
                MessageBox.Show("Error: Wprowadź wartość E lub D.");
            }
            else
            {
                return true;
            }

            return false;
        }
        #endregion
        #region private bool IsPublicKeyValid(out BigInteger eps, out BigInteger r). Sprawdź wejście
        private bool IsPublicKeyValid(out BigInteger eps, out BigInteger r)
        {

            r = eps = 0;

            if (!BigInteger.TryParse(tbR.Text, out r))
            {
                MessageBox.Show("Error: Nieprawidłowa wartość R.");
            }
            else if (!BigInteger.TryParse(tbE.Text, out eps))
            {
                MessageBox.Show("Error: Nieprawidłowa wartość E.");
            }
            else if (eps >= r)
            {
                MessageBox.Show("Error: E musi być mniejsze niż R.");
            }
            else
            {
                return true;
            }

            return false;
        }

        #endregion

        #endregion

        private void tbMessage_TextChanged(object sender, TextChangedEventArgs e)
        {

        }
    }
}
