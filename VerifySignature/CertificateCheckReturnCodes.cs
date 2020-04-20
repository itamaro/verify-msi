namespace VerifySignature
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
