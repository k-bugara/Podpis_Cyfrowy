using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Windows;

namespace Digital_Signature
{
    public class SHA_1
    {


        #region Fields 
        //   private int HashBitCount = 62; // liczba znaczących bitów w haszu

        private byte[] _Buffer;
           private long _Count; // liczba bajtów w tekście
        private uint[] _StateSHA1; // hash
           private uint[] _ExpandedBuffer;         
        #endregion

        #region Constructor
        public SHA_1()
        {
            _StateSHA1 = new uint[5]; // długość hash'a = 5 32-bitowych liczb całkowitych = 160 bitów
            _Buffer = new byte[64]; // długość bloku tekstu = 64 bajtów = 512 bitów
            _ExpandedBuffer = new uint[80]; 
        }
        #endregion

        #region Methods
        #region public GetHash(byte[] text). Zwraca skrót SHA-1 dla tablicy bajtów
        public SHA_1_Hash GetHash(byte[] text)
        {
            SHA_1_Hash result = new SHA_1_Hash();

            //byte[] buffer = Encoding.GetEncoding("utf-8"/*1251*/).GetBytes(text);
            byte[] buffer = new byte[text.Length];
            Array.Copy(text, buffer, text.Length);

            Initialize();

            HashData(buffer, 0, buffer.Length);

            result.Value = EndHash();
            
            return result;
        }
        #endregion

        #region private void Initialize(). Initialize _StateSHA1.
        private void Initialize()
        {
            _Count = 0;

            _StateSHA1[0] = 0x67452301;
            _StateSHA1[1] = 0xefcdab89;
            _StateSHA1[2] = 0x98badcfe;
            _StateSHA1[3] = 0x10325476;
            _StateSHA1[4] = 0xc3d2e1f0;
        }
        #endregion
        #region private unsafe void HashData(byte[] partIn, int ibStart, int cbSize). Zwraca skrót głównej części tekstu.
        private unsafe void HashData(byte[] partIn, int ibStart, int cbSize)
        {
            int bufferLen = (int) _Count & 0x3f; // maksymalna długość tekstu 2^64 bitów (0x3f = 00111111 = 63)
            int partInLen = cbSize; // liczba zahashowanych bajtów
            int partInBase = ibStart; // pierwszy bajt do hashowania

            _Count += partInLen; // zaktualizuj liczbę bajtów

            // napraw lokalizację tablic
            fixed (uint* stateSHA1 = _StateSHA1)
            {
                fixed (byte* buffer = _Buffer)
                {
                    fixed (uint* expandedBuffer = _ExpandedBuffer)
                    {
                        // coś jest już w buforze
                        if ((bufferLen > 0) && (bufferLen + partInLen >= 64))
                        {
                            Buffer.BlockCopy(partIn, partInBase, _Buffer, bufferLen, 64 - bufferLen);
                            partInBase += (64 - bufferLen);
                            partInLen -= (64 - bufferLen);
                            SHA_1_Transform(expandedBuffer, stateSHA1, buffer);
                            bufferLen = 0;
                        }

                        while (partInLen > 64)
                        {
                            Buffer.BlockCopy(partIn, partInBase, _Buffer, 0, 64);
                            partInBase += 64;
                            partInLen -= 64;

                            // obliczyć skrót
                            SHA_1_Transform(expandedBuffer, stateSHA1, buffer);
                        }

                        // napraw resztę
                        if (partInLen > 0)
                            Buffer.BlockCopy(partIn, partInBase, _Buffer, bufferLen, partInLen);
                    } 
                }
            }
        }
        #endregion
        #region private static unsafe void SHA_1_Transform(uint* expandedBuffer, uint* state, byte* block). Hashowanie
        private static unsafe void SHA_1_Transform(uint* expandedBuffer, uint* state, byte* block)
        {

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];

            uint i, temp, f, k;

            DWORDFromBigEndian(expandedBuffer, 16, block); //16 32-bit DWORDs
            SHAExpand(expandedBuffer); //16 32-bit DWORDs to 80 32-bit DWORDs

            // główna pętla
            for (i = 0; i < 80; i++)
            {

                f = 0; k = 0;

                if ((i >= 0) && (i < 20))
                {
                    f = (((b) & (c)) | ((~(b)) & (d))); // Ft(b,c,d)
                    k = 0x5A827999;
                }
                else if ((i >= 20) && (i < 40))
                {
                    f = ((b) ^ (c) ^ (d)); // Ft(b,c,d)
                    k = 0x6ED9EBA1;
                }
                else if ((i >= 40) && (i < 60))
                {
                    f = (((b) & (c)) | ((b) & (d)) | ((c) & (d))); // Ft(b,c,d)
                    k = 0x8F1BBCDC;
                }
                else if ((i >= 60) && (i < 80))
                {
                    f = ((b) ^ (c) ^ (d)); // Ft(b,c,d)
                    k = 0xCA62C1D6;
                }

                temp = (((a)) << (5)) | (((a)) >> (32 - (5))); // a <<< 5
                temp += (f + e + k + expandedBuffer[i]);
                e = d;
                d = c;
                c = (((b)) << (30)) | (((b)) >> (32 - (30)));
                b = a;
                a = temp;

            }

            // dodaj hash do wyniku
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;

        }
        #endregion
        #region internal unsafe static void DWORDFromBigEndian(uint* x, int digits, byte* block). 
        internal unsafe static void DWORDFromBigEndian(uint* x, int digits, byte* block)
        {
            for (int i = 0, j = 0; i < digits; i++, j += 4)
                x[i] = (uint)((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]);
        }
        #endregion
        #region private static unsafe void SHAExpand(uint* x). Oblicz wt.
        private static unsafe void SHAExpand(uint* x)
        {
            int i;
            uint tmp;

            for (i = 16; i < 80; i++)
            {
                tmp = (x[i - 3] ^ x[i - 8] ^ x[i - 14] ^ x[i - 16]); // Wt
                x[i] = ((tmp << 1) | (tmp >> 31));  // okrągłe przesunięcie w lewo o 1
            }
        }
        #endregion
        #region private byte[] EndHash(). Oblicz ostatnią porcję
        private byte[] EndHash()
        {
            byte[] pad;
            int padLen;
            long bitCount;
            byte[] hash = new byte[20]; // 160 bitów

            padLen = 64 - (int)(_Count & 0x3f); // maksymalna długość tekstu 2^64 bitów (0x3f = 00111111 = 63)
            if (padLen <= 8) // 64 bitów
                padLen += 64;

            pad = new byte[padLen];
            pad[0] = 0x80; // 1000 0000

            bitCount = _Count * 8;

            pad[padLen - 8] = (byte)((bitCount >> 56) & 0xff);
            pad[padLen - 7] = (byte)((bitCount >> 48) & 0xff);
            pad[padLen - 6] = (byte)((bitCount >> 40) & 0xff);
            pad[padLen - 5] = (byte)((bitCount >> 32) & 0xff);
            pad[padLen - 4] = (byte)((bitCount >> 24) & 0xff);
            pad[padLen - 3] = (byte)((bitCount >> 16) & 0xff);
            pad[padLen - 2] = (byte)((bitCount >> 8) & 0xff);
            pad[padLen - 1] = (byte)((bitCount >> 0) & 0xff);

            // hash ostatniego fragmentu
            HashData(pad, 0, pad.Length);

            DWORDToBigEndian(hash, _StateSHA1, 5);

            return hash;
        }
        #endregion
        #region internal unsafe static void DWORDToBigEndian(byte[] block, uint[] x, int digits).
        internal unsafe static void DWORDToBigEndian(byte[] block, uint[] x, int digits)
        {
            int i;
            int j;

            for (i = 0, j = 0; i < digits; i++, j += 4)
            {
                block[j] = (byte)((x[i] >> 24) & 0xff);
                block[j + 1] = (byte)((x[i] >> 16) & 0xff);
                block[j + 2] = (byte)((x[i] >> 8) & 0xff);
                block[j + 3] = (byte)(x[i] & 0xff);
            }
        }
        #endregion
        #endregion

    }
}
