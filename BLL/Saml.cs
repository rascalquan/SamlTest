using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;

namespace SeamTest2.BLL
{
    public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
    {
        public RSAPKCS1SHA256SignatureDescription()
        {
            KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            DigestAlgorithm = typeof(SHA256Managed).FullName;   // Note - SHA256CryptoServiceProvider is not registered with CryptoConfig
            FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");
            return formatter;
        }

        private static bool _initialized = false;
        public static void Init()
        {
            if (!_initialized)
                CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            _initialized = true;
        }
    }

    public class Certificate
    {
        public X509Certificate2 cert;

        public void LoadCertificate(string certificate)
        {
            cert = new X509Certificate2();
            cert.Import(StringToByteArray(certificate));
        }

        public void LoadCertificate(byte[] certificate)
        {
            cert = new X509Certificate2();
            cert.Import(certificate);
        }

        private byte[] StringToByteArray(string st)
        {
            byte[] bytes = new byte[st.Length];
            for (int i = 0; i < st.Length; i++)
            {
                bytes[i] = (byte)st[i];
            }
            return bytes;
        }

        public void LoadCertificate(string fileName, string password, X509KeyStorageFlags keystoreageflag)
        {
            cert= new X509Certificate2("server.p12", "pass", keystoreageflag);
        }

        public void  GetSigningCertificate()
        {
            var cer = Convert.FromBase64String("MIIDUjCCAjqgAwIBAgIEUOLIQTANBgkqhkiG9w0BAQUFADBrMQswCQYDVQQGEwJGSTEQMA4GA1UECBMHVXVzaW1hYTERMA8GA1UEBxMISGVsc2lua2kxGDAWBgNVBAoTD1JNNSBTb2Z0d2FyZSBPeTEMMAoGA1UECwwDUiZEMQ8wDQYDVQQDEwZhcG9sbG8wHhcNMTMwMTAxMTEyODAxWhcNMjIxMjMwMTEyODAxWjBrMQswCQYDVQQGEwJGSTEQMA4GA1UECBMHVXVzaW1hYTERMA8GA1UEBxMISGVsc2lua2kxGDAWBgNVBAoTD1JNNSBTb2Z0d2FyZSBPeTEMMAoGA1UECwwDUiZEMQ8wDQYDVQQDEwZhcG9sbG8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXqP0wqL2Ai1haeTj0alwsLafhrDtUt00E5xc7kdD7PISRA270ZmpYMB4W24Uk2QkuwaBp6dI/yRdUvPfOT45YZrqIxMe2451PAQWtEKWF5Z13F0J4/lB71TtrzyH94RnqSHXFfvRN8EY/rzuEzrpZrHdtNs9LRyLqcRTXMMO4z7QghBuxh3K5gu7KqxpHx6No83WNZj4B3gvWLRWv05nbXh/F9YMeQClTX1iBNAhLQxWhwXMKB4u1iPQ/KSaal3R26pONUUmu1qVtU1quQozSTPD8HvsDqGG19v2+/N3uf5dRYtvEPfwXN3wIY+/R93vBA6lnl5nTctZIRsyg0Gv5AgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAFQwAAYUjso1VwjDc2kypK/RRcB8bMAUUIG0hLGL82IvnKouGixGqAcULwQKIvTs6uGmlgbSG6Gn5ROb2mlBztXqQ49zRvi5qWNRttir6eyqwRFGOM6A8rxj3Jhxi2Vb/MJn7XzeVHHLzA1sV5hwl/2PLnaL2h9WyG9QwBbwtmkMEqUt/dgixKb1Rvby/tBuRogWgPONNSACiW+Z5o8UdAOqNMZQozD/i1gOjBXoF0F5OksjQN7xoQZLj9xXefxCFQ69FPcFDeEWbHwSoBy5hLPNALaEUoa5zPDwlixwRjFQTc5XXaRpgIjy/2gsL8+Y5QRhyXnLqgO67BlLYW/GuHE=");
            var pkey =
                Convert.FromBase64String(
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCXqP0wqL2Ai1haeTj0alwsLafhrDtUt00E5xc7kdD7PISRA270ZmpYMB4W24Uk2QkuwaBp6dI/yRdUvPfOT45YZrqIxMe2451PAQWtEKWF5Z13F0J4/lB71TtrzyH94RnqSHXFfvRN8EY/rzuEzrpZrHdtNs9LRyLqcRTXMMO4z7QghBuxh3K5gu7KqxpHx6No83WNZj4B3gvWLRWv05nbXh/F9YMeQClTX1iBNAhLQxWhwXMKB4u1iPQ/KSaal3R26pONUUmu1qVtU1quQozSTPD8HvsDqGG19v2+/N3uf5dRYtvEPfwXN3wIY+/R93vBA6lnl5nTctZIRsyg0Gv5AgMBAAECggEBAJZmt1jnLq9pAWEP8MSrKeeCC4iJBnnYImBnUKn5zLcq6Ajrz8A+RN5aMazXXK4TMsEUsqH2iVRKd4HIuTP3v6G5lumFxM2B4wJzcA6WgKBN+yAciAZ3ppd3+qrKytn8v3eRDoKiiWM1kmUbwbnOTg4aNIGxplfwHxdCt7lEmgUPIpkZvHaytidIZI2cn/3twteiiwLezJib5MBKYsGt2Q7UVTgJL7QI33p16UfQH7KE053zOyUSW1PJr2Ai3ltHUoNNAL+LhLlLdQZ5/c+MR20ZV+1XMavmdFRWwqsYA732vEpT0mpznaP901kz1NX6JLqnqFl4m1IHQJVy/dLMBOUCgYEA54eb1U6dxKx4R+ev5NpIbDY0mSKHamRqxz5JE8iEQk6jtnM5DR5kH4iLbW2N0W3nmm6yp46QclT7QEggijZJ/IoSh4RLoafiS0+kYgXN+CK+0eoDVENiljYTpI8gmvFgQ0G094fWfU7P9du97tKjr2jqJNqpwvVcrd7xIHjm64sCgYEAp7BivZVOZNK5aLohYcsL48956ohlpRxnDlScKXco2y5AoPZiKr0ApvDSHYLmyVFbAAsOGOhjorGrv4e+T0yilq51NFTybvwmQKO2PcqN0T2ery0VwDk1Lwk4jejV7bhH1LeBweFCInHwqLXf5L+ZpcuI+vf58L5WPbnX3QfKhwsCgYAfw3P2lJ2CYOLzgm6YJ/YtmlYm+By51OLtSLc/1o+GhUFig3Y9PYEg7luqfJArPje68Rrjb+STOuNpUzvbmk0WL18RZm311JFwIZH8vK0gMKwbIk6oncIFt4+EUPp5J0o8j+Qi3WjosgpHwYjSHeXE59DPk4wcqgq389EC0nNjtwKBgHMOhIF+O37UU2E3LQZzkiHqTsWMdum2NkPP7CJLX14cOz32L98RNaxV2mVjVsTVLHI4I6EVep+79pMBKaQxefGXnFWe34UlP33klnuJSotCE2owrhbpacNvOT2tf3OPmMGsc7y6uWz27uBjgk7q5BqtL7y7fuQfRP8vT5yZ5u2HAoGBALMzjbrAqFdrMFay70+AH4JP97ibs9N8nk1DY+Y2YamT3+8S8em3zKBLA/kqMGfbVZ459NoD1UrnfeAYULXlPPYg5qmTqP8TM54n6REYwwiDPLSi1rBNZEjXtYSK/woyfTGFMH4ba6TpxTkhWT5BeuzZSScaCWlTSpIm7cvCmW1Z");

            var x509 = new X509Certificate2(cer);
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString("<RSAKeyValue><Modulus>l6j9MKi9gItYWnk49GpcLC2n4aw7VLdNBOcXO5HQ+zyEkQNu9GZqWDAeFtuFJNkJLsGgaenSP8kXVLz3zk+OWGa6iMTHtuOdTwEFrRClheWddxdCeP5Qe9U7a88h/eEZ6kh1xX70TfBGP687hM66Wax3bTbPS0ci6nEU1zDDuM+0IIQbsYdyuYLuyqsaR8ejaPN1jWY+Ad4L1i0Vr9OZ214fxfWDHkApU19YgTQIS0MVocFzCgeLtYj0Pykmmpd0duqTjVFJrtalbVNarkKM0kzw/B77A6hhtfb9vvzd7n+XUWLbxD38Fzd8CGPv0fd7wQOpZ5eZ03LWSEbMoNBr+Q==</Modulus><Exponent>AQAB</Exponent><P>54eb1U6dxKx4R+ev5NpIbDY0mSKHamRqxz5JE8iEQk6jtnM5DR5kH4iLbW2N0W3nmm6yp46QclT7QEggijZJ/IoSh4RLoafiS0+kYgXN+CK+0eoDVENiljYTpI8gmvFgQ0G094fWfU7P9du97tKjr2jqJNqpwvVcrd7xIHjm64s=</P><Q>p7BivZVOZNK5aLohYcsL48956ohlpRxnDlScKXco2y5AoPZiKr0ApvDSHYLmyVFbAAsOGOhjorGrv4e+T0yilq51NFTybvwmQKO2PcqN0T2ery0VwDk1Lwk4jejV7bhH1LeBweFCInHwqLXf5L+ZpcuI+vf58L5WPbnX3QfKhws=</Q><DP>H8Nz9pSdgmDi84JumCf2LZpWJvgcudTi7Ui3P9aPhoVBYoN2PT2BIO5bqnyQKz43uvEa42/kkzrjaVM725pNFi9fEWZt9dSRcCGR/LytIDCsGyJOqJ3CBbePhFD6eSdKPI/kIt1o6LIKR8GI0h3lxOfQz5OMHKoKt/PRAtJzY7c=</DP><DQ>cw6EgX47ftRTYTctBnOSIepOxYx26bY2Q8/sIktfXhw7PfYv3xE1rFXaZWNWxNUscjgjoRV6n7v2kwEppDF58ZecVZ7fhSU/feSWe4lKi0ITajCuFulpw285Pa1/c4+YwaxzvLq5bPbu4GOCTurkGq0vvLt+5B9E/y9PnJnm7Yc=</DQ><InverseQ>szONusCoV2swVrLvT4Afgk/3uJuz03yeTUNj5jZhqZPf7xLx6bfMoEsD+SowZ9tVnjn02gPVSud94BhQteU89iDmqZOo/xMznifpERjDCIM8tKLWsE1kSNe1hIr/CjJ9MYUwfhtrpOnFOSFZPkF67NlJJxoJaVNKkibty8KZbVk=</InverseQ><D>lma3WOcur2kBYQ/wxKsp54ILiIkGedgiYGdQqfnMtyroCOvPwD5E3loxrNdcrhMywRSyofaJVEp3gci5M/e/obmW6YXEzYHjAnNwDpaAoE37IByIBneml3f6qsrK2fy/d5EOgqKJYzWSZRvBuc5ODho0gbGmV/AfF0K3uUSaBQ8imRm8drK2J0hkjZyf/e3C16KLAt7MmJvkwEpiwa3ZDtRVOAkvtAjfenXpR9AfsoTTnfM7JRJbU8mvYCLeW0dSg00Av4uEuUt1Bnn9z4xHbRlX7Vcxq+Z0VFbCqxgDvfa8SlPSanOdo/3TWTPU1fokuqeoWXibUgdAlXL90swE5Q==</D></RSAKeyValue>");

            x509.PrivateKey = rsa;
            cert= x509;
        }
    }

    public class Response
    {
        private XmlDocument xmlDoc;
        private AccountSettings accountSettings;
        private Certificate certificate;

        public Response(AccountSettings accountSettings)
        {
            RSAPKCS1SHA256SignatureDescription.Init();

            this.accountSettings = accountSettings;
            certificate = new Certificate();
            //certificate.LoadCertificate(accountSettings.certificate);
            certificate.GetSigningCertificate();
        }

        public void LoadXml(string xml)
        {
            xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.XmlResolver = null;
            xmlDoc.LoadXml(xml);
        }

        public void LoadXmlFromBase64(string response)
        {
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            LoadXml(enc.GetString(Convert.FromBase64String(response)));
        }

        public bool IsValid()
        {
            bool status = true;

            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            XmlNodeList nodeList = xmlDoc.SelectNodes("//ds:Signature", manager);

            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);

            status &= signedXml.CheckSignature(certificate.cert, true);

            var notBefore = NotBefore();
            status &= !notBefore.HasValue || (notBefore <= DateTime.Now);

            var notOnOrAfter = NotOnOrAfter();
            status &= !notOnOrAfter.HasValue || (notOnOrAfter > DateTime.Now);

            return status;
        }

        public DateTime? NotBefore()
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            var nodes = xmlDoc.SelectNodes("/samlp:Response/saml:Assertion/saml:Conditions", manager);
            string value = null;
            if (nodes != null && nodes.Count > 0 && nodes[0] != null && nodes[0].Attributes != null && nodes[0].Attributes["NotBefore"] != null)
            {
                value = nodes[0].Attributes["NotBefore"].Value;
            }
            return value != null ? DateTime.Parse(value) : (DateTime?)null;
        }

        public DateTime? NotOnOrAfter()
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            var nodes = xmlDoc.SelectNodes("/samlp:Response/saml:Assertion/saml:Conditions", manager);
            string value = null;
            if (nodes != null && nodes.Count > 0 && nodes[0] != null && nodes[0].Attributes != null && nodes[0].Attributes["NotOnOrAfter"] != null)
            {
                value = nodes[0].Attributes["NotOnOrAfter"].Value;
            }
            return value != null ? DateTime.Parse(value) : (DateTime?)null;
        }

        public string GetNameID()
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            XmlNode node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", manager);
            return node.InnerText;
        }

        private bool ValidateSignatureReference(SignedXml signedXml)
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            if (signedXml.SignedInfo.References.Count != 1) //no ref at all
                return false;

            var reference = (Reference)signedXml.SignedInfo.References[0];
            var id = reference.Uri.Substring(1);

            var idElement = signedXml.GetIdElement(xmlDoc, id);

            if (idElement == xmlDoc.DocumentElement)
                return true;
            else //sometimes its not the "root" doc-element that is being signed, but the "assertion" element
            {
                var assertionNode = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", manager) as XmlElement;
                if (assertionNode != idElement)
                    return false;
            }

            return true;
        }

        private bool IsExpired()
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            DateTime expirationDate = DateTime.MaxValue;
            XmlNode node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", manager);
            if (node != null && node.Attributes["NotOnOrAfter"] != null)
            {
                DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
            }
            return DateTime.UtcNow > expirationDate.ToUniversalTime();
        }
    }

    public class AuthRequest
    {
        public string id;
        private string issue_instant;
        private AppSettings appSettings;
        private AccountSettings accountSettings;

        public enum AuthRequestFormat
        {
            Base64 = 1
        }

        public AuthRequest(AppSettings appSettings, AccountSettings accountSettings)
        {
            this.appSettings = appSettings;
            this.accountSettings = accountSettings;

            id = "_" + System.Guid.NewGuid().ToString();
            issue_instant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }

        public string GetRequest(AuthRequestFormat format)
        {
            var xml = new XmlDocument();
            using (StringWriter sw = new StringWriter())
            {
                XmlWriterSettings xws = new XmlWriterSettings();
                xws.OmitXmlDeclaration = true;

                using (XmlWriter xw = XmlWriter.Create(sw, xws))
                {
                    xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("ID", id);
                    xw.WriteAttributeString("Version", "2.0");
                    xw.WriteAttributeString("IssueInstant", issue_instant);
                    xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
                    xw.WriteAttributeString("AssertionConsumerServiceURL", appSettings.assertionConsumerServiceUrl);

                    xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xw.WriteString(appSettings.issuer);
                    xw.WriteEndElement();

                    xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
                    xw.WriteAttributeString("AllowCreate", "true");
                    xw.WriteEndElement();

                    xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("Comparison", "exact");

                    xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                    xw.WriteEndElement();

                    xw.WriteEndElement(); // RequestedAuthnContext

                    xw.WriteEndElement();

                    //xml.LoadXml(xw.ToString());
                }
                //xml.LoadXml(xws.ToString());
                //var certificate = new Certificate();
                ////certificate.LoadCertificate(accountSettings.certificate);
                //certificate.LoadCertificate("server.p12", "pass", X509KeyStorageFlags.Exportable);
                //EncryptXmlWithCert(xml, "", certificate.cert);

                if (format == AuthRequestFormat.Base64)
                {

                    byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(xws.ToString());
                    return System.Convert.ToBase64String(toEncodeAsBytes);
                }

                return null;
            }
        }

        public static void EncryptXmlWithCert(XmlDocument Doc, string ElementToEncrypt, X509Certificate2 Cert)
        {
            // Check the arguments.  
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (ElementToEncrypt == null)
                throw new ArgumentNullException("ElementToEncrypt");
            if (Cert == null)
                throw new ArgumentNullException("Cert");

            ////////////////////////////////////////////////
            // Find the specified element in the XmlDocument
            // object and create a new XmlElemnt object.
            ////////////////////////////////////////////////

            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;
            // Throw an XmlException if the element was not found.
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");

            }

            //////////////////////////////////////////////////
            // Create a new instance of the EncryptedXml class 
            // and use it to encrypt the XmlElement with the 
            // X.509 Certificate.
            //////////////////////////////////////////////////

            EncryptedXml eXml = new EncryptedXml();

            // Encrypt the element.
            EncryptedData edElement = eXml.Encrypt(elementToEncrypt, Cert);

            ////////////////////////////////////////////////////
            // Replace the element from the original XmlDocument
            // object with the EncryptedData element.
            ////////////////////////////////////////////////////
            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
        }

        public string GetRedirectUrl(string samlEndpoint)
        {
            var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";

            return samlEndpoint + queryStringSeparator + "SAMLRequest=" + HttpUtility.UrlEncode(this.GetRequest(AuthRequest.AuthRequestFormat.Base64));
        }
    }
}