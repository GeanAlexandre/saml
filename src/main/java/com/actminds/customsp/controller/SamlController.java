package com.actminds.customsp.controller;

import com.actminds.customsp.service.SAMLParser;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.io.UnmarshallingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

@RestController
public class SamlController {

    private SAMLParser samlParser;

    @Autowired
    public SamlController(SAMLParser samlParser) {
        this.samlParser = samlParser;
    }

    @RequestMapping(value = "/parseSaml", method = RequestMethod.POST)
    public String parseSaml(HttpServletRequest request) throws Exception {
        Response response = this.samlParser.parse(request.getParameter("SAMLResponse"));

        return response.getIssuer().getValue();
    }
}
