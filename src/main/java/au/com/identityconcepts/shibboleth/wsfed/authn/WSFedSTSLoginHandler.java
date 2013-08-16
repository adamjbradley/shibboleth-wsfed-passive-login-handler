package au.com.identityconcepts.shibboleth.wsfed.authn;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import org.opensaml.util.URLBuilder;
 


import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;

import java.io.FileInputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.SAML1AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethSAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.AttributeDefinition;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;

public class WSFedSTSLoginHandler extends AbstractLoginHandler {
 
     /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedSTSLoginHandler.class);
 
    private XMLObjectBuilder<Signature> signatureBuilder;
    private HashMap<String, String> attributeMap;

    /** The URL of the servlet used to perform authentication. */
    private String authenticationServletURL;
 
    /**
     * Constructor.
     *
     * @param servletURL URL to the authentication servlet
     */
    public WSFedSTSLoginHandler(String servletURL) {
        super();
        log.debug("WSFedLoginHandler constructor (entering)");

        setSupportsPassive(false);
        setSupportsForceAuthentication(true);
        authenticationServletURL = servletURL;
    }
    
    public void login(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {
 
        // forward control to the servlet
        try {
            StringBuilder pathBuilder = new StringBuilder();
            pathBuilder.append(httpRequest.getContextPath());
            if(!authenticationServletURL.startsWith("/")){
                pathBuilder.append("/");
            }
 
            pathBuilder.append(authenticationServletURL);
 
            URLBuilder urlBuilder = new URLBuilder();
            urlBuilder.setScheme(httpRequest.getScheme());
            urlBuilder.setHost(httpRequest.getServerName());
            urlBuilder.setPort(httpRequest.getServerPort());
            urlBuilder.setPath(pathBuilder.toString());
 
            log.debug("Redirecting to {}", urlBuilder.buildURL());
            httpResponse.sendRedirect(urlBuilder.buildURL());
            return;
 
        } catch (IOException ex) {
            log.error("Unable to redirect to authentication servlet.", ex);
        }
    }
}