using Konscious.Security.Cryptography;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HashArgon2
{
    public class ClassHashArgon2
    {
        public int EntDegreeOfParallelism = 8; // 4 cores de processador
        public int EntIterations = 2;
        public int EntMemorySize = 1024;
        private byte[] pass = {0x3A, 0xF1, 0x9C, 0x47, 0xE2, 0x0D, 0xB8, 0x6F, 0x54, 0xA9, 0x1E, 0xD3, 0x88, 0x72, 0xC5, 0x0B}; // senha para o hash

        private byte[] CriaSalt()
        {
            var buffer = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(buffer);
            return buffer;
        }

        // Gerar o hash da string desejada usando Argon2
        public byte[] GerarHash(string palavra)
        {
            byte[] salt = CriaSalt();
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(palavra));

            argon2.Salt = salt;
            argon2.DegreeOfParallelism = EntDegreeOfParallelism;
            argon2.Iterations = EntIterations;
            argon2.MemorySize = EntMemorySize;
            
            argon2.KnownSecret = pass;

            return argon2.GetBytes(16).Concat(salt).ToArray();
        }

        // Verificar se a string digitada corresponde ao hash armazenado
        public bool VerificarHash(string password,byte[] hash)
        {
            byte[] salt = new byte[16];
            byte[] hash2 = new byte[16];

            int d = 0;

            for (int i = 0; i < 32; i++)
            {
                if (i < 16)
                {
                    hash2[i] = hash[i];
                }
                else
                {
                    salt[d] = hash[i];
                    d++;
                }
            }

            var newHash = HashPassword(password, salt);
            return hash2.SequenceEqual(newHash);
        }
        
        private byte[] HashPassword(string password, byte[] salt)
        {

            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));

            argon2.Salt = salt;
            argon2.DegreeOfParallelism = EntDegreeOfParallelism;
            argon2.Iterations = EntIterations;
            argon2.MemorySize = EntMemorySize;
            argon2.KnownSecret = pass;

            return argon2.GetBytes(16).ToArray();
        }
    }
}
