namespace ThreeShape.AuthenticodeSigning.Verification
{
    public enum CertificateCheckReturnCodes
    {
        Success,
        DoesNotPassAuthenticodeVerification,
        ValidMsiButSignatureDnsNameMismatch,
        CertificateForMsiNotValidProbablySelfSigned,
        NoValidDigitalSignatureOnMsi,
    }
}
