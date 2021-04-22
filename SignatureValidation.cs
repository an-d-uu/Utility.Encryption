
using System;
using System.Security.Cryptography;

namespace Utility.Encryption
{
#if NET40
    public enum eCryptographyType
    {
        HMACMD5 = 0,
        HMACRIPEMD160 = 1,
        HMACSHA1 = 2,
        HMACSHA256 = 3,
        HMACSHA384 = 4

    }
#elif NET5_0_OR_GREATER
    public enum eCryptographyType
    {
        HMACMD5 = 0,
        HMACSHA1 = 2,
        HMACSHA256 = 3,
        HMACSHA384 = 4,
        HMACSHA512 = 5
    }
#else
    public enum eCryptographyType
    {
        HMACMD5 = 0,
        HMACRIPEMD160 = 1,
        HMACSHA1 = 2,
        HMACSHA256 = 3,
        HMACSHA384 = 4,
        HMACSHA512 = 5
    }
#endif

    public class SignatureValidation
    {
        /// <summary>
        /// Validates the signature.
        /// </summary>
        /// <returns>true or false</returns>
        public static bool ValidSignature(string signature, string data, string secret, eCryptographyType cryptography)
        {
            bool returnValue;
            try
            {
                string hashedDataSig = HashData(data, secret, cryptography);

                if (hashedDataSig == signature)
                {
                    returnValue = true;
                }
                else
                {
                    returnValue = false;
                }
            }
            catch
            {
                returnValue = false;
            }

            return returnValue;
        }

#if NET40
        public static string HashData(string data, string secret, eCryptographyType cryptography)
        {
            string returnValue = string.Empty;
            secret = secret ?? "";
            var encoding = new System.Text.UTF8Encoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(data);

            switch (cryptography)
            {
                case eCryptographyType.HMACRIPEMD160:
                    {

                        using (HMACRIPEMD160 hashfunction = new HMACRIPEMD160(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACMD5:
                    {

                        using (HMACMD5 hashfunction = new HMACMD5(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA1:
                    {

                        using (HMACSHA1 hashfunction = new HMACSHA1(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA256:
                    {
                        using (HMACSHA256 hashfunction = new HMACSHA256(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA384:
                    {
                        using (HMACSHA384 hashfunction = new HMACSHA384(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
            }

            return returnValue;
        }
#elif NET5_0_OR_GREATER
        public static string HashData(string data, string secret, eCryptographyType cryptography)
        {
            string returnValue = string.Empty;
            secret = secret ?? "";
            var encoding = new System.Text.UTF8Encoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(data);

            switch (cryptography)
            {
                case eCryptographyType.HMACMD5:
                    {

                        using (HMACMD5 hashfunction = new HMACMD5(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA1:
                    {

                        using (HMACSHA1 hashfunction = new HMACSHA1(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA256:
                    {
                        using (HMACSHA256 hashfunction = new HMACSHA256(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA384:
                    {
                        using (HMACSHA384 hashfunction = new HMACSHA384(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA512:
                    {
                        using (HMACSHA512 hashfunction = new HMACSHA512(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
            }

            return returnValue;
        }
#else
        public static string HashData(string data, string secret, eCryptographyType cryptography)
        {
            string returnValue = string.Empty;
            secret = secret ?? "";
            var encoding = new System.Text.UTF8Encoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(data);

            switch (cryptography)
            {
                case eCryptographyType.HMACRIPEMD160:
                    {

                        using (HMACRIPEMD160 hashfunction = new HMACRIPEMD160(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACMD5:
                    {

                        using (HMACMD5 hashfunction = new HMACMD5(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA1:
                    {

                        using (HMACSHA1 hashfunction = new HMACSHA1(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA256:
                    {
                        using (HMACSHA256 hashfunction = new HMACSHA256(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA384:
                    {
                        using (HMACSHA384 hashfunction = new HMACSHA384(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
                case eCryptographyType.HMACSHA512:
                    {
                        using (HMACSHA512 hashfunction = new HMACSHA512(keyByte))
                        {
                            byte[] hashmessage = hashfunction.ComputeHash(messageBytes);
                            returnValue = Convert.ToBase64String(hashmessage);
                        }
                        break;
                    }
            }

            return returnValue;
        }
#endif
    }
}
