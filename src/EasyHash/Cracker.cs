using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace EasyHash
{
    public class Cracker
    {
        private readonly string _path;
        private readonly Action<string> _log;

        private readonly byte[] _salt;
        private readonly byte[] _header;

        public Cracker(string path, Action<string> log)
        {
            _path = path;
            _log = log;
            _salt = new byte[8];
            _header = new byte[16];
        }

        public string FindPassword()
        {
            ReadSalt();

            var passwords = new[] {"for_fail", "123", "test"};
            foreach (var password in passwords)
            {
                if (CheckPassword(password))
                {
                    return password;
                }
            }

            return "";
        }

        private bool CheckPassword(string password)
        {
            var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            var buffer = Encoding.Unicode.GetBytes(password);
            byte[] iv = new byte[16];
            int[] digestInts;
            byte[] digestBytes = new byte[16];


            for (int i = 0; i < 0x40000; i++)
            {
                sha1.AppendData(buffer);
                sha1.AppendData(_salt);
                sha1.AppendData(new[]
                {
                    (byte) i,
                    (byte) (i >> 8),
                    (byte) (i >> 16)
                });

                if ((i % (0x40000 / 16)) == 0)
                {
                    digestInts = ConvertToInts(sha1.GetCurrentHash());
                    iv[i / (0x40000 / 16)] = (byte) Reverse(digestInts[4]);
                }
            }

            digestInts = ConvertToInts(sha1.GetCurrentHash());
            for (int i = 0; i < 5; i++)
            {
                digestInts[i] = Reverse(digestInts[i]);
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    digestBytes[i * 4 + j] = (byte) (digestInts[i] >> (j * 8));
                }
            }

            using var aes = AesManaged.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            var decryptor = aes.CreateDecryptor(digestBytes, iv);
            using (MemoryStream msDecrypt = new(_header))
            {
                using (CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    var result = new byte[16];


                    csDecrypt.Read(result);
                    if (Enumerable.SequenceEqual(
                        new byte[] {0xC4, 0x3D, 0x7B, 0x0, 0x40, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, result))
                    {
                        _log("Found!");
                        return true;
                    }
                }
            }

            return false;
        }

        private int[] ConvertToInts(byte[] bytes)
        {
            var size = bytes.Count() / sizeof(int);
            var ints = new int[size];
            for (var index = 0; index < size; index++)
            {
                ints[index] = BitConverter.ToInt32(bytes, index * sizeof(int));
            }

            return ints;
        }

        private int Reverse(int value)
        {
            var bytes = BitConverter.GetBytes(value);
            return BitConverter.ToInt32(Enumerable.Reverse(bytes).ToArray());
        }

        private void ReadSalt()
        {
            using var reader = new BinaryReader(File.OpenRead(_path));

            var signature = new byte[7];
            reader.Read(signature);

            if (!signature.SequenceEqual(new byte[] {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}))
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
                            _log("Encrypted");
                            reader.BaseStream.Seek(-24, SeekOrigin.End);

                            reader.Read(_salt);
                            reader.Read(_header);

                            return;
                        }
                        break;
                }
            }
        }
    }
}