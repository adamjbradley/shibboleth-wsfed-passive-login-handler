package au.com.identityconcepts.shibboleth.test.conf1;

import au.com.identityconcepts.shibboleth.test.*;
import au.com.identityconcepts.shibboleth.test.conf1.*;

import java.security.Principal;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;

//import org.opensaml.saml2.core.AuthnRequest;
//import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml1.core.*;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

import java.security.Principal;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;


/**
 * Unit test for simple App.
 */
public class WSFedLoginHandlerTest extends BaseConf1TestCase 
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public WSFedLoginHandlerTest( String testName )
    {
        super( );
    }

    /**
     * Parse incoming WS-Fed token
     * @throws ProfileException 
     */
    public void ParseWSFedTokenTest() throws Exception
    {
        MockServletContext servletContext = new MockServletContext();

        MockHttpServletRequest servletRequest = buildServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        AbstractShibbolethProfileHandler handler = (AbstractShibbolethProfileHandler) handlerManager
                .getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);
        
        assertTrue( true );
    }
    
    protected MockHttpServletRequest buildServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setPathInfo("/shibboleth/SSO");
        request.setParameter("providerId", "urn:example.org:sp1");
        request.setParameter("shire", "https://example.org/mySP");
        request.setParameter("target", "https://example.org/mySP");

        return request;
    }

}
