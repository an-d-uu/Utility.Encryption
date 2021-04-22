
namespace Utility.Encryption
{
    public static class Extensions
    {
        private static readonly System.DateTime epoch = new System.DateTime(1970, 1, 1, 0, 0, 0, System.DateTimeKind.Utc);

        /// <summary>
        /// Adds a useful epoch datetime function for including in hashing and validating signatures
        /// </summary>
        /// <param name="unixTime"></param>
        /// <returns></returns>
        public static System.DateTime FromUnixTimeMilliseconds(long unixTime)
        {
            return epoch.AddMilliseconds(unixTime);
        }
        /// <summary>
        /// Adds a useful epoch datetime function for including in hashing and validating signatures
        /// </summary>
        /// <param name="unixTime"></param>
        /// <returns></returns>
        public static System.DateTime FromUnixTimeSeconds(long unixTime)
        {
            return epoch.AddSeconds(unixTime);
        }

        /// <summary>
        /// Adds a useful epoch datetime function for including in hashing and validating signatures
        /// </summary>
        /// <param name="date"></param>
        /// <returns></returns>
        public static long ToUnixTimeMilliseconds(System.DateTime date)
        {
            return (long)(date - epoch).TotalMilliseconds;
        }

        /// <summary>
        /// Adds a useful epoch datetime function for including in hashing and validating signatures
        /// </summary>
        /// <param name="unixTime"></param>
        /// <returns></returns>
        public static long ToUnixTimeSeconds(System.DateTime date)
        {
            return (long)(date - epoch).TotalSeconds;
        }
    }
}
