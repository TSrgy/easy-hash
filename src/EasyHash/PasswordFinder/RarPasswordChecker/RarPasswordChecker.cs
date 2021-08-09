using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using EasyHash.Algorithms;
using ILGPU;
using ILGPU.Runtime;
using SHA1 = EasyHash.Algorithms.SHA1;

namespace EasyHash.PasswordFinder.RarPasswordChecker
{
    public abstract class RarPasswordChecker : AsyncPasswordChecker
    {
        public const int sizeOfIV = 16;
        public const int sizeOfDigestInts = 5;
        private readonly string _path;
        protected readonly byte[] _salt;
        protected readonly byte[] _header;

        public RarPasswordChecker(string path, IEnumerable<string> passwords, Action<string> callback)
            : base(passwords, callback)
        {
            _path = path;
            _salt = new byte[8];
            _header = new byte[16];
        }

        public override async Task StartCheckingAllPasswordsAsync()
        {
            InitHeaderAndSalt();

            await StartLoop();
        }

        protected abstract Task StartLoop();

        private void InitHeaderAndSalt()
        {
            using var reader = new BinaryReader(File.OpenRead(_path));

            var signature = new byte[7];
            reader.Read(signature);

            if (!signature.SequenceEqual(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 }))
            {
                throw new Exception("It's not RAR3 archive!");
            }

            while (true)
            {
                reader.ReadInt16(); //CRC

                var headType = reader.ReadByte();
                switch (headType)
                {
                    case 0x74:
                        throw new NotImplementedException();
                    case 0x73:
                        var flags = reader.ReadInt16();

                        if ((flags & 0x0080) != 0)
                        {
                            reader.BaseStream.Seek(-24, SeekOrigin.End);

                            reader.Read(_salt);
                            reader.Read(_header);
                        }

                        return;
                }
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="salt"></param>
        /// <returns>
        /// size of digestInts = 5
        /// size of iv = 16
        /// </returns>
        public static AesParams CalcDigestGpu(ArrayView<byte> buffer, ArrayView<byte> salt)
        {
            // using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            var sha1 = new SHA1Gpu(1);
            var iv = LocalMemory.Allocate<byte>(sizeOfIV);
            // var iv = new byte[sizeOfIV];
            ArrayView<int> digestInts;

            //TODO For GPU
            for (int i = 0; i < 0x40000; i++)
            {
                sha1.AppendData(buffer);
                sha1.AppendData(salt);
                sha1.AppendData(new[]
                {
                    (byte)i,
                    (byte)(i >> 8),
                    (byte)(i >> 16)
                }.AsArrayView());

                if ((i % (0x40000 / 16)) == 0)
                {
                    digestInts = Utils.ConvertToInts(sha1.GetCurrentHash(), 20);

                    iv[i / (0x40000 / 16)] = (byte)(digestInts[4] >> 24);
                }
            }

            digestInts = Utils.ConvertToInts(sha1.GetCurrentHash(), 20);
            return new AesParams()
            {
                digest = digestInts,
                iv = iv
            };
        }


        /// <summary>
        ///
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="salt"></param>
        /// <returns>
        /// size of digestInts = 5
        /// size of iv = 16
        /// </returns>
        public static (int[] digest, byte[] iv) CalcDigest(byte[] buffer, byte[] salt)
        {
            // using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            var sha1 = new SHA1(1);
            var iv = new byte[sizeOfIV];
            int[] digestInts;

            //TODO For GPU
            for (int i = 0; i < 0x40000; i++)
            {
                sha1.AppendData(buffer);
                sha1.AppendData(salt);
                sha1.AppendData(new[]
                {
                    (byte)i,
                    (byte)(i >> 8),
                    (byte)(i >> 16)
                });

                if ((i % (0x40000 / 16)) == 0)
                {
                    digestInts = Utils.ConvertToInts(sha1.GetCurrentHash(), 20);

                    iv[i / (0x40000 / 16)] = (byte)(digestInts[4] >> 24);
                }
            }

            digestInts = Utils.ConvertToInts(sha1.GetCurrentHash(), 20);
            return (digestInts, iv);
        }


        protected static bool CheckPassword(byte[] header, int[] digestInts, byte[] iv)
        {
            var digestBytes = new byte[16];


            for (int i = 0; i < 5; i++)
            {
                digestInts[i] = Reverse(digestInts[i]);
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    digestBytes[i * 4 + j] = (byte)(digestInts[i] >> (j * 8));
                }
            }

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            var decryptor = aes.CreateDecryptor(digestBytes, iv);
            using MemoryStream msDecrypt = new(header);
            using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
            var result = new byte[16];
            csDecrypt.Read(result);
            return new byte[] { 0xC4, 0x3D, 0x7B, 0x0, 0x40, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }.SequenceEqual(result);
        }


        static int Reverse(int value)
        {
            var bytes = BitConverter.GetBytes(value);
            var resultBytes = new[] { bytes[3], bytes[2], bytes[1], bytes[0] };
            return BitConverter.ToInt32(resultBytes);
        }
    }
}