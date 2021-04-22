using System;

namespace Utility.Encryption
{
    public class SigningObject
    {
        private long epoch { get; set; }
        private eCryptographyType cryptographyType { get; set; }
        private string signature { get; set; }
        private string secret { get; set; }

        public SigningObject() : base()
        {
            cryptographyType = eCryptographyType.HMACSHA256;
            SetEpoch();
            signature = string.Empty;
        }
        public SigningObject(string secret, string value2Sign = "", eCryptographyType cryptographyType = eCryptographyType.HMACSHA256) : base()
        {
            SetEpoch();
            SetSecret(secret);
            SetCryptographyType(cryptographyType);
            CreateSignature(value2Sign);
        }

        public static SigningObject Create(string secret, string value2Sign = "", eCryptographyType cryptographyType = eCryptographyType.HMACSHA256)
        {
            return new SigningObject(secret, value2Sign, cryptographyType);
        }

        public void SetEpoch()
        {
            epoch = Extensions.ToUnixTimeSeconds(DateTime.UtcNow);
        }

        public void SetSecret(string value)
        {
            secret = value;
        }

        #region "SetCryptographyType"

        public void SetCryptographyType(object value)
        {
            SetCryptographyType(value.ToString());
        }
        public void SetCryptographyType(int value)
        {
            SetCryptographyType(value.ToString());
        }
#if NET40
        public void SetCryptographyType(string value)
        {
            switch (value.ToUpper())
            {
                case "0":
                case "HMACMD5":
                    cryptographyType = eCryptographyType.HMACMD5;
                    break;
                case "1":
                case "HMACRIPEMD160":
                    cryptographyType = eCryptographyType.HMACRIPEMD160;
                    break;
                case "2":
                case "HMACSHA1":
                    cryptographyType = eCryptographyType.HMACSHA1;
                    break;
                case "4":
                case "HMACSHA384":
                    cryptographyType = eCryptographyType.HMACSHA384;
                    break;
                default:
                    cryptographyType = eCryptographyType.HMACSHA256;
                    break;
            }

        }
#elif NET5_0_OR_GREATER
        public void SetCryptographyType(string value)
        {
            cryptographyType = value.ToUpper() switch
            {
                "0" or "HMACMD5" => eCryptographyType.HMACMD5,
                "2" or "HMACSHA1" => eCryptographyType.HMACSHA1,
                "4" or "HMACSHA384" => eCryptographyType.HMACSHA384,
                "5" or "HMACSHA512" => eCryptographyType.HMACSHA512,
                _ => eCryptographyType.HMACSHA256,
            };
        }
#else
        public void SetCryptographyType(string value)
        {
            switch (value.ToUpper())
            {
                case "0":
                case "HMACMD5":
                    cryptographyType = eCryptographyType.HMACMD5;
                    break;
                case "1":
                case "HMACRIPEMD160":
                    cryptographyType = eCryptographyType.HMACRIPEMD160;
                    break;
                case "2":
                case "HMACSHA1":
                    cryptographyType = eCryptographyType.HMACSHA1;
                    break;
                case "4":
                case "HMACSHA384":
                    cryptographyType = eCryptographyType.HMACSHA384;
                    break;
                case "5":
                case "HMACSHA512":
                    cryptographyType = eCryptographyType.HMACSHA512;
                    break;
                default:
                    cryptographyType = eCryptographyType.HMACSHA256;
                    break;
            }

        }
#endif

        public void SetCryptographyType(eCryptographyType value)
        {
            cryptographyType = value;
        }

        #endregion

        public void CreateSignature(string secret, string value2Sign = "", eCryptographyType cryptographyType = eCryptographyType.HMACSHA256)
        {
            SetSecret(secret);
            SetCryptographyType(cryptographyType);
            CreateSignature(value2Sign);
        }
        public void CreateSignature(string value = "")
        {
            if (!(string.IsNullOrEmpty(secret)))
            {

                string string2Hash = string.IsNullOrEmpty(value) ? string.Format("{0}|{1}", DateTimeOffset.UtcNow.Date, epoch) : string.Format("{0}|{1}", value, epoch);
                signature = SignatureValidation.HashData(string2Hash, secret, cryptographyType);
            }
            else
                throw new Exception("Secret is missing and you must run SetSecret(\"value\") before creating the signature!");
        }

        public string GetSignature()
        {
            if (!(string.IsNullOrEmpty(signature)))
                return signature;
            else
            {
                CreateSignature();
                return signature;
            }

        }
    }
}
