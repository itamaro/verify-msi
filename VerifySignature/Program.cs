using System.Data;

namespace VerifySignature
{
    class Program
    {
        static void Main(string[] args)
        {
            var returnCode = MsiTools.VerifyMsiSignature(args[0], args[1]);
            if (returnCode != CertificateCheckReturnCodes.Success)
            {
                throw new DataException(returnCode.ToString());
            }
        }
    }
}
