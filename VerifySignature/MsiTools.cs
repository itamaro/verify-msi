using System;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using VerifySignature;

namespace VerifySignature
{
    public static class MsiTools
    {
        public static CertificateCheckReturnCodes VerifyMsiSignature(string msiPath, string expectedDnsName)
        {
            if (!File.Exists(msiPath))
            {
                throw new ArgumentException($"File does not exist: {msiPath}");
            }

            // check Authenticode validity on MSI
            if (!AuthenticodeTools.IsTrusted(msiPath))
            {
                return CertificateCheckReturnCodes.DoesNotPassAuthenticodeVerification;
            }

            try
            {
                var signer = X509Certificate.CreateFromSignedFile(msiPath);
                var certificate = new X509Certificate2(signer);
                // verify certificate chain
                var certificateChain = new X509Chain();
                certificateChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                certificateChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                certificateChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromMinutes(1.0f);
                certificateChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                if (certificateChain.Build(certificate))
                {
                    return certificate.GetNameInfo(X509NameType.DnsName, false) == expectedDnsName ? CertificateCheckReturnCodes.Success : CertificateCheckReturnCodes.ValidMsiButSignatureDnsNameMismatch;
                }
                else
                {
                    return CertificateCheckReturnCodes.CertificateForMsiNotValidProbablySelfSigned;
                }
            }
            catch (Exception)
            {
                return CertificateCheckReturnCodes.NoValidDigitalSignatureOnMsi;
            }
            finally
            {
                Trace.Flush();
            }
        }
    }
}
