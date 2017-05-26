package com.actminds.customsp.service;

import org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

public class DBMetadataProvider extends AbstractReloadingMetadataProvider {
    private final String IDP_METADATA = "<?xml version=\"1.0\"?>\n" +
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2017-05-28T14:16:47Z\" cacheDuration=\"PT1496413007S\" entityID=\"http://idp.example.com/metadata.php\" ID=\"pfx6230abf2-0af3-6017-ef40-9687c3de1e5c\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
            "  <ds:Reference URI=\"#pfx6230abf2-0af3-6017-ef40-9687c3de1e5c\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>B0N9O3HCYtrAwwmHl15lxLNF3X8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>K7+pmLXZ1EqIg/moHTlvdjfzz+12bUXWmuutIgQGtZz3aII0bRStWif3n4kVKYnLcJ1rBL8iOdtiHuMUV5y8XZemQ0vdWpxPvsyFpFGzNZeiSWgN078TlkexQzp0Ostgr80+8cJIUmP2SdItkzpPFRWHv0yT8bAMok5A4Wg8tE8=</ds:SignatureValue>\n" +
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEOMAwGA1UECAwFc3RhdGUxGDAWBgNVBAoMD2lkcG9yZ2FuaXphdGlvbjEWMBQGA1UEAwwNaWRwZG9tYWluLmNvbTAeFw0xNzA1MjYxMjQwMzNaFw0xODA1MjYxMjQwMzNaME8xCzAJBgNVBAYTAnVzMQ4wDAYDVQQIDAVzdGF0ZTEYMBYGA1UECgwPaWRwb3JnYW5pemF0aW9uMRYwFAYDVQQDDA1pZHBkb21haW4uY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVFSx3MCByBvN0s3Oxovn40GTl/lQ+M5ToVOFqZ67/4KbKOqHZi85Bs5pg51aqvqheSLNPe7ab/+fK3S34x+7hY6BSj6vb4UjtsqJ/scX02tjKNfL1WDduu+/kXJWmPV1fRrcbVTe1ymZWV8ICzjsh8nhhFkDHRYutH/oa+G+SJwIDAQABo1AwTjAdBgNVHQ4EFgQU+4HhVZ63jyPpAYIFdwsFo66bk4QwHwYDVR0jBBgwFoAU+4HhVZ63jyPpAYIFdwsFo66bk4QwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQBL69/j/tDTNOh8skps323uKkEF+K9dA9+elYWx42kV59KuYY+/JtlXUjwCPhvySBA6CkaAcc/H4H/180l9bHUsG+hqWS94wEMDELzav9e6HV1yE+97FDJKcNM31i7rBaWwf7h/s3r9yvPglJU8zuTXHwbAiz9Ip0cIZBoT97YsFA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
            "    <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
            "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n" +
            "       <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://idp.example.com\"/>\n" +
            "    </md:IDPSSODescriptor>\n" +
            "</md:EntityDescriptor>\n";

    private String metaDataEntityId;

    public DBMetadataProvider(String entityId) {
        super();
        setMetaDataEntityId(entityId);
    }

    public void setMetaDataEntityId(String metaDataEntityId){
        this.metaDataEntityId = metaDataEntityId;
    }

    public String getMetaDataEntityId() {
        return this.metaDataEntityId;
    }

    @Override
    protected String getMetadataIdentifier() {
        return getMetaDataEntityId();
    }

    @Override
    protected byte[] fetchMetadata() throws MetadataProviderException {
        return IDP_METADATA.getBytes(StandardCharsets.UTF_8);
    }
}
