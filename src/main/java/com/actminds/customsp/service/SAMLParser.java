package com.actminds.customsp.service;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.impl.EntitiesDescriptorImpl;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.KeyAlgorithmCriteria;
import org.opensaml.xml.security.criteria.PublicKeyCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509DigestCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.validation.Schema;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

@Service
public class SAMLParser {

    public SAMLParser() throws ConfigurationException {
        // Initialize the library
        DefaultBootstrap.bootstrap();
    }

    public Response parse(String samlResponse) throws XMLParserException, SAXException, UnmarshallingException, MetadataProviderException, ValidationException, SecurityException {
        // Initialize DBMetadata Provider
        DBMetadataProvider dbMetadataProvider = new DBMetadataProvider("http://idp.example.com/metadata.php");
        dbMetadataProvider.setRequireValidMetadata(true);
        dbMetadataProvider.setParserPool(new BasicParserPool());
        dbMetadataProvider.initialize();

        // Unmarshall SAML Response Posted
        Response response = unmarshall(samlResponse);

        // Validate Signature is in a proper format
        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(response.getSignature());

        // Validate Signature is trusted
        MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver(dbMetadataProvider);
        KeyInfoCredentialResolver keyInfoCredentialResolver = Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
        ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine = new ExplicitKeySignatureTrustEngine(metadataCredentialResolver, keyInfoCredentialResolver);
        SignatureTrustEngine signatureTrustEngine = explicitKeySignatureTrustEngine;
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(response.getIssuer().getValue()));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        //criteriaSet.add(new KeyAlgorithmCriteria())
        Boolean isValid = signatureTrustEngine.validate(response.getSignature(), criteriaSet);

        if (isValid)
            return response;

        throw new RuntimeException("invalid response");
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