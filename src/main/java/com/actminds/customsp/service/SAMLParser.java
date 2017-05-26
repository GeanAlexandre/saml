package com.actminds.customsp.service;

import org.apache.xml.security.keys.keyresolver.InvalidKeyResolverException;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.CollectionKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Util;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class SAMLParser {
    private String cert = "MIICOjCCAaOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADA6MQswCQYDVQQGEwJ1czENMAsGA1UECAwEZ2VhbjENMAsGA1UECgwEZ2VhbjENMAsGA1UEAwwEZ2VhbjAeFw0xNzA1MjYxNzU5MDJaFw0xODA1MjYxNzU5MDJaMDoxCzAJBgNVBAYTAnVzMQ0wCwYDVQQIDARnZWFuMQ0wCwYDVQQKDARnZWFuMQ0wCwYDVQQDDARnZWFuMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdDEwk43Dcko56yhKdr5zABUEw5Uxnb5pNT0EPWkc1F2+T5y7N7kOWmNgurgypOILNw9VRvgDVqgdiWgL8Onj08LDwgeH3o0kfUOEsxtUqv/lqkenJjT4xJL3RklCQfz/AWRorCO7hJg8Dy1syDbiBofRvjcMOWf7YiFn1tTPXIQIDAQABo1AwTjAdBgNVHQ4EFgQUlyJuHZllJCu+272enf8paj7xavcwHwYDVR0jBBgwFoAUlyJuHZllJCu+272enf8paj7xavcwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQBw0Euc+bQlYmWDm5++48a8eZ6T2w6C/6BY7XQc/r0C0VbQRPvm1wlpnq+pmmbKI2KSq9tuqeRaSyTdJLPc5tiwB4yyLRonTT8tWYHpl6l66lFH YVmp9xJN41c+pc4codmYy4U4AkqTUAPG1eWTLTc58llMSMbSC1VxyYpoNl7q7w==";
    private String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJ0MTCTjcNySjnrKEp2vnMAFQTDlTGdvmk1PQQ9aRzUXb5PnLs3uQ5aY2C6uDKk4gs3D1VG+ANWqB2JaAvw6ePTwsPCB4fejSR9Q4SzG1Sq/+WqR6cmNPjEkvdGSUJB/P8BZGisI7uEmDwPLWzINuIGh9G+Nww5Z/tiIWfW1M9chAgMBAAECgYAog8KlBZPZI2nkXXsd+O78Tp65yX3DdXQeG6MSHd0e4jPjuRFHCP+guz+SE06q3SxJfwrqMpUuidWr1sLMZR1M08Z25vJ/Ly/KiYL/X0q5ERHTaMaVJtv+Hx+ItFvkbmgSC/1pF2xXAymvffn1oMmahChVnXgjiR7hpJTI0eOMrQJBAM6qG/F7U4Qki82hb6O7d+aZ8fh2NcVdMOyH04xsd0rA8a117zaLMekSJrJs97XjZ6tULCvyVcmWbfhzN3ao20cCQQDCifojsWS6c4OMfhBKa/z0nUmHsMArX1+YWbqsrrZPdH0tWmq30wt5PbC46RXyRhlYoAY+OJPXdhufJHwYaR5XAkEAh471fVST153RRjSach/J6i0Ylw2S/769FKmTjgynwxUEce9l1bVAK82ILIllgp2DptIzlzACLZTK1aldvCvOiQJARPGVPrUNl658fnvm1hkzSpW7i2UulbB1No8GQ1Cft8T23+3dSEx5Eny0drPUXUpOjUQZMk/mxUNMQrgxao1GfQJAQxl8kOfTPu7Te5HgRZrTgWKXzmwU0HK3yOFl/pXMogN5P8mIRhVrko3qsq3di9dYj7S+6M21187RnXaV5ei05A==";

    public SAMLParser() throws ConfigurationException {
        // Initialize the library
        DefaultBootstrap.bootstrap();
    }

    public Response parse(String samlResponse) throws Exception {

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

        Document document = docBuilder.parse(new InputSource(new StringReader(samlResponse)));
        Element element = document.getDocumentElement();

        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        XMLObject responseXmlObj = unmarshaller.unmarshall(element);

        Response response = (Response) responseXmlObj;

        Assertion assertion = response.getAssertions().get(0);
        String subject = assertion.getSubject().getNameID().getValue();
        String issuer = assertion.getIssuer().getValue();
        String audience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI();
        String statusCode = response.getStatus().getStatusCode().getValue();
        Signature sig = response.getSignature();
        X509Certificate certificate = getCertificate(cert);
        SignatureValidator validator = new SignatureValidator(SecurityHelper.getSimpleCredential(certificate,null));
        validator.validate(sig);

        if(isValid(response))
            return response;

        throw new RuntimeException();
    }

    public boolean isValid(SignableSAMLObject object) {
        try {
            List<Credential> trustedCredentials = new ArrayList<>();
            X509Certificate certificate = getCertificate(cert);
            trustedCredentials.add(SecurityHelper.getSimpleCredential(certificate,null));
            verifyObjectIsSigned(object);
            return validateSignature(object, trustedCredentials);

        } catch (SecurityException e) {
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void verifyObjectIsSigned(SignableSAMLObject object) throws SecurityException {
        if (object.getSignature() == null) {
            throw new SecurityException("SAML object is not signed");
        }
    }


    private static java.security.cert.X509Certificate getCertificate(String certificate) throws Exception {
        try {
            Collection<java.security.cert.X509Certificate> certificates =
                    X509Util.decodeCertificate(Base64.decode(certificate));
            return certificates
                    .stream()
                    .findFirst()
                    .orElseThrow(() -> new Exception("Cannot load certificate"));
        } catch (CertificateException ex) {
            throw new Exception("Cannot load certificate", ex);
        }
    }

    private boolean validateSignature(SignableSAMLObject object, List<Credential> trustedCredentials) throws SecurityException {
        KeyInfoCredentialResolver keyInfoResolver = new CollectionKeyInfoCredentialResolver(trustedCredentials);
        CollectionCredentialResolver credentialResolver = new CollectionCredentialResolver(trustedCredentials);
        SignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoResolver);
        CriteriaSet criteriaSet = buildCriteriaSet();
        return trustEngine.validate(object.getSignature(), criteriaSet);
    }

    /**
     * Builds the criteria set used to validate the signature.
     *
     * @return the new criteria set.
     */
    private CriteriaSet buildCriteriaSet() {
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        return criteriaSet;
    }

    @SuppressWarnings("unchecked")
    private <T> T unmarshall(String samlResponse) throws SAXException, XMLParserException, UnmarshallingException {
        // Schema
        Schema schema = SAMLSchemaBuilder.getSAML11Schema();

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);
        ppMgr.setSchema(schema);

        // Parse metadata file
        InputStream in = new ByteArrayInputStream(samlResponse.getBytes(StandardCharsets.UTF_8));
        Document inCommonMDDoc = ppMgr.parse(in);
        Element metadataRoot = inCommonMDDoc.getDocumentElement();

        // Get apropriate unmarshaller
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);

        // Unmarshall using the document root element, an SAMLObject in this case
        return (T)(unmarshaller.unmarshall(metadataRoot));
    }
}