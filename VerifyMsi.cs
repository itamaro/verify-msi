using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace CommonLib
{
    public class MsiTools
    {
        private static bool VerifyMsiSignature(string msiPath)
        {
            // check Authenticode validity on MSI
            if (!AuthenticodeTools.IsTrusted(msiPath))
            {
                Trace.TraceError("MSI {0} does not pass Authenticode verification", msiPath);
                return false;
            }
            try
            {
                X509Certificate signer = X509Certificate.CreateFromSignedFile(msiPath);
                X509Certificate2 certificate = new X509Certificate2(signer);
                // verify certificate chain
                var certificateChain = new X509Chain();
                certificateChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                certificateChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                certificateChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromMinutes(1.0f);
                certificateChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                if (certificateChain.Build(certificate))
                {
                    Trace.TraceInformation(
                        "Verified Authenticode certificate chain for MSI {0} subject is {1}",
                        msiPath, certificate.Subject);
                    if (certificate.GetNameInfo(X509NameType.DnsName, false) ==
                        Properties.Settings.Default.ExpectedSignatureDnsName)
                    {
                        Trace.TraceInformation("Valid signed MSI - all is well");
                        return true;
                    }
                    else
                    {
                        Trace.TraceError("Valid MSI, but signature DNS name mismatch!");
                        return false;
                    }
                }
                else
                {
                    Trace.TraceError("Certificate for MSI {0} not valid (probably self-signed)", msiPath);
                    return false;
                }
            }
            catch (Exception ex)
            {
                // no digital signature on file
                Trace.TraceError("No valid digital signature on MSI {0}: {1}",
                    msiPath, ex.Message);
                return false;
            }
        }
    }
}
