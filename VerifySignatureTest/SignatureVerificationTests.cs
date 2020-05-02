using System.IO;
using NUnit.Framework;
using VerifySignature;

namespace VerifySignatureTest
{
    public class SignatureVerificationTests
    {
        private static readonly string _testProjectFolder = Directory.GetCurrentDirectory() + "/../../..";

        [Test]
        public void NotSigned()
        {
            var returnCode = MsiTools.VerifyMsiSignature($"{_testProjectFolder}/data/NotSigned.dll", "3Shape A/S");
            Assert.AreEqual(CertificateCheckReturnCodes.DoesNotPassAuthenticodeVerification, returnCode);
        }

        [Test]
        public void Signed3shape()
        {
            var returnCode = MsiTools.VerifyMsiSignature($"{_testProjectFolder}/data/Signed3Shape.dll", "3Shape A/S");
            Assert.AreEqual(CertificateCheckReturnCodes.Success, returnCode);
        }

        [Test]
        public void Signed3shapeButWrongDNSName()
        {
            var returnCode = MsiTools.VerifyMsiSignature($"{_testProjectFolder}/data/Signed3Shape.dll", "Wrong name");
            Assert.AreEqual(CertificateCheckReturnCodes.ValidMsiButSignatureDnsNameMismatch, returnCode);
        }
    }
}
