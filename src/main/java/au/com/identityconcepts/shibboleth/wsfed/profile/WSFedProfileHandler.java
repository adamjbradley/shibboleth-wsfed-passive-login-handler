package au.com.identityconcepts.shibboleth.wsfed.profile;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
import au.com.identityconcepts.shibboleth.wsfed.authn.WSFedLoginContext;
import au.com.identityconcepts.shibboleth.wsfed.config.relyingparty.WSFedClaim;
import au.com.identityconcepts.shibboleth.wsfed.config.relyingparty.WSFedConfiguration;

import java.io.IOException;
import java.io.StringReader;
import java.io.Writer;
import java.io.OutputStreamWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.*;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLConstants;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;


import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;
import edu.internet2.middleware.shibboleth.idp.profile.saml1.*;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;

import org.opensaml.common.SAMLObject;

import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.AbstractSAMLProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.profile.saml1.*;

public class WSFedProfileHandler extends AbstractSAML1ProfileHandler {
	   	
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedProfileHandler.class);

    /** Builder of AuthenticationStatement objects. */
    private SAMLObjectBuilder<AuthenticationStatement> authnStatementBuilder;

    /** Builder of SubjectLocality objects. */
    private SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder;

    /** Builder of Endpoint objects. */
    private SAMLObjectBuilder<Endpoint> endpointBuilder;

    /** URL of the authentication manager servlet. */
    private String authenticationManagerPath;

    private String wsFedRelyingParty = "urn:mace:shibboleth:2.0:infocard:default-dont-use";
    protected String relyingParty = wsFedRelyingParty;  // actually comes from config  

    
    public final static String XMLNS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
    public final static String XMLNS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
    public final static String XMLNS_IC = "http://schemas.xmlsoap.org/ws/2005/05/identity";
    public final static String XMLNS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public final static String XMLNS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public final static String XMLNS_WSA = "http://www.w3.org/2005/08/addressing";
    public final static String XMLNS_WST = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public final static String XMLNS_WSP = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public final static String XMLNS_WSID = "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity";
    public final static String SAML_ASSERTIONID = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID";
    public final static String XMLNS_DS = "http://www.w3.org/2000/09/xmldsig#";
    public final static String XMLNS_XENC = "http://www.w3.org/2001/04/xmlenc#";
    public final static String subjectConfMethod = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";
    public final static String XMLNS_SAML = "urn:oasis:names:tc:SAML:1.0:assertion";
    private X509Certificate realRPCert = null;

    
	/**
	 * Constructor.
	 * 
	 */	
	public WSFedProfileHandler(String authnManagerPath, String rp) {
        if (DatatypeHelper.isEmpty(authnManagerPath)) {
            throw new IllegalArgumentException("Authentication manager path may not be null");
        }
        if (authnManagerPath.startsWith("/")) {
            authenticationManagerPath = authnManagerPath;
        } else {
            authenticationManagerPath = "/" + authnManagerPath;
        }

        authnStatementBuilder = (SAMLObjectBuilder<AuthenticationStatement>) getBuilderFactory().getBuilder(
                AuthenticationStatement.DEFAULT_ELEMENT_NAME);

        subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) getBuilderFactory().getBuilder(
                SubjectLocality.DEFAULT_ELEMENT_NAME);

        endpointBuilder = (SAMLObjectBuilder<Endpoint>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        
        relyingParty = rp;
	}
		
    /** {@inheritDoc} */
    public String getProfileId() {
        return WSFedConfiguration.PROFILE_ID;
    }
    
    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {

    	log.debug("WSFed Profile handler processing incomming request");
    	    
    	HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpServletResponse httpResponse = ((HttpServletResponseAdapter) outTransport).getWrappedResponse();
        ServletContext servletContext = httpRequest.getSession().getServletContext();

        LoginContext loginContext = HttpServletHelper.getLoginContext(getStorageService(),
                servletContext, httpRequest);
    	
        if(loginContext != null){
            HttpServletHelper.unbindLoginContext(getStorageService(), servletContext, httpRequest, httpResponse);
            
            if(!(loginContext instanceof WSFedLoginContext)){
                log.debug("Incoming request contained a login context but it was not a ShibbolethSSOLoginContext, processing as first leg of request");
                performAuthentication(inTransport, outTransport);
                return;
            }        
            
            if(loginContext.isPrincipalAuthenticated()){
                log.debug("Incoming request contains a login context and indicates principal was authenticated, processing second leg of request");
                completeAuthenticationRequest((WSFedLoginContext)loginContext, inTransport, outTransport);
                return;
            }
            
            if(loginContext.getAuthenticationFailure() != null){
                log.debug("Incoming request contains a login context and indicates there was an error authenticating the principal, processing second leg of request");
                completeAuthenticationRequest((WSFedLoginContext)loginContext, inTransport, outTransport);
                return;
            }

            log.debug("Incoming request contains a login context but principal was not authenticated, processing first leg of request");
            performAuthentication(inTransport, outTransport);
            return;
            
        }
        
        log.debug("Incoming request does not contain a login context, processing as first leg of request");
        performAuthentication(inTransport, outTransport);
        return;
    }
        

	/**
     * Creates a {@link LoginContext} an sends the request to the AuthenticationManager to authenticate the user.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if there is a problem creating the login context and transferring control to the
     *             authentication manager
     */
	protected void performAuthentication(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        log.debug("WSFed performAuthentication");
        
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpServletResponse httpResponse = ((HttpServletResponseAdapter) outTransport).getWrappedResponse();
        WSFedRequestContext requestContext = new WSFedRequestContext();

        decodeRequest(requestContext, inTransport, outTransport);
        WSFedLoginContext loginContext = requestContext.getLoginContext();                       
                
        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingParty);
        //loginContext.setDefaultAuthenticationMethod(method);
        
        HttpServletHelper.bindLoginContext(loginContext, getStorageService(), httpRequest.getSession()
                .getServletContext(), httpRequest, httpResponse);

        try {
            String authnEngineUrl = HttpServletHelper.getContextRelativeUrl(httpRequest, authenticationManagerPath)
                    .buildURL();
            log.debug("Redirecting user to authentication engine at {}", authnEngineUrl);
            httpResponse.sendRedirect(authnEngineUrl);
        } catch (IOException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Unable to perform user authentication"));
            String msg = "Error forwarding Shibboleth SSO request to AuthenticationManager";
            log.error(msg, e);
            throw new ProfileException(msg, e);
        }
        
    }
    
    /**
     * Decodes an incoming request and populates a created request context with the resultant information.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * @param requestContext the request context to which decoded information should be added
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected void decodeRequest(WSFedRequestContext requestContext, HTTPInTransport inTransport,
            HTTPOutTransport outTransport) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Decoding message with decoder binding {}", getInboundMessageDecoder(requestContext)
                    .getBindingURI());
        }
        
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();

        requestContext.setMetadataProvider(getMetadataProvider());
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());

        requestContext.setCommunicationProfileId(WSFedConfiguration.PROFILE_ID);
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        /*
        SAMLMessageDecoder decoder = getInboundMessageDecoder(requestContext);
        requestContext.setMessageDecoder(decoder);
        try {
            decoder.decode(requestContext);
            log.debug("Decoded Shibboleth SSO request from relying party '{}'",
                    requestContext.getInboundMessageIssuer());
        } catch (MessageDecodingException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Error decoding request"));
            String msg = "Error decoding Shibboleth SSO request";
            log.warn(msg, e);
            throw new ProfileException(msg, e);
        } catch (SecurityException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Request does not meet security requirements"));
            String msg = "Shibboleth SSO request does not meet security requirements: " + e.getMessage();
            log.warn(msg);
            throw new ProfileException(msg, e);
        }
        */

        WSFedLoginContext loginContext = new WSFedLoginContext();
        loginContext.setRelyingParty(requestContext.getInboundMessageIssuer());
        loginContext.setSpAssertionConsumerService(requestContext.getSpAssertionConsumerService());
        loginContext.setSpTarget(requestContext.getRelayState());
        loginContext.setAuthenticationEngineURL(authenticationManagerPath);
        loginContext.setProfileHandlerURL(HttpHelper.getRequestUriWithoutContext(httpRequest));
        requestContext.setLoginContext(loginContext);
        
    }
    
    private void completeAuthenticationRequest(WSFedLoginContext loginContext,
			HTTPInTransport inTransport, HTTPOutTransport outTransport) {
    	
    	//Element response = buildResponse(loginContext);
    	Element response = null; 
    	
    	outTransport.addParameter("wctx",inTransport.getParameterValue("wctx"));

        try {
             HTTPTransportUtils.addNoCacheHeaders(outTransport);
             HTTPTransportUtils.setUTF8Encoding(outTransport);
             HTTPTransportUtils.setContentType(outTransport, "application/soap+xml");
             Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
             XMLHelper.writeNode(response, out);
             out.flush();
        } catch (Exception e) {
             log.error("sts write response: " +  e);
        }
          
        log.info("STS reply completed.");		
	}

    
    
    /**
     * Creates a response to the Shibboleth SSO and sends the user, with response in tow, back to the relying party
     * after they've been authenticated.
     * 
     * @param loginContext login context for this request
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if the response can not be created and sent back to the relying party
     */
    protected void completeAuthenticationRequestOLD(WSFedLoginContext loginContext, HTTPInTransport inTransport,
            HTTPOutTransport outTransport) throws ProfileException {
        WSFedRequestContext requestContext = buildRequestContext(loginContext, inTransport, outTransport);

        boolean rethrow = false;
        Response samlResponse;
        try {
            if (loginContext.getAuthenticationFailure() != null) {
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "User failed authentication"));
                throw new ProfileException("Authentication failure", loginContext.getAuthenticationFailure());
            }

            Session session = getUserSession(requestContext.getInboundMessageTransport());
            if (session == null) {
                rethrow = true;
                log.warn("Authentication failure, session missing during completion of profile handler");
                throw new ProfileException("Authentication failure, session missing during completion of profile handler");
            }
                        
			resolveAttributes(requestContext);

			/*
            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAuthenticationStatement(requestContext));
            if (requestContext.getProfileConfiguration().includeAttributeStatement()) {
                AttributeStatement attributeStatement = buildAttributeStatement(requestContext,
                        "urn:oasis:names:tc:SAML:1.0:cm:bearer");
                if (attributeStatement != null) {
                    requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());
                    statements.add(attributeStatement);
                }
            }            
            samlResponse = buildResponse(requestContext, statements);
                        
            // If a NameIdentifier is being returned to an SP, index the user's session with it.
            NameIdentifier nameID = requestContext.getSubjectNameIdentifier();
            if (nameID != null && samlResponse.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS)) {
                ServiceInformationImpl serviceInfo =
                        (ServiceInformationImpl) session.getServicesInformation().get(requestContext.getPeerEntityId());
                serviceInfo.setShibbolethNameIdentifier(nameID);
                SessionManager<Session> sessionManager = getSessionManager();
                if (sessionManager != null) {
                    String index = getSessionIndexFromNameID(nameID);
                    if (index != null && !index.isEmpty()) {
                        log.debug("secondarily indexing user session by name identifier");
                        sessionManager.indexSession(session, index);
                    }
                }
            }
            */                        
        } catch (ProfileException e) {
            if (rethrow) {
                // Passes the error to the global error handler.
                throw e;
            }
            samlResponse = buildErrorResponse(requestContext);
        }

        /*
        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        */
        
        encodeResponse(requestContext);        
        writeAuditLogEntry(requestContext);        
    }
    
    /**
     * Builds the authentication statement for the authenticated principal.
     * 
     * @param requestContext current request context
     * 
     * @return the created statement
     * 
     * @throws ProfileException thrown if the authentication statement can not be created
     */
    protected AuthenticationStatement buildAuthenticationStatement(WSFedRequestContext requestContext)
            throws ProfileException {
        WSFedLoginContext loginContext = requestContext.getLoginContext();

        AuthenticationStatement statement = authnStatementBuilder.buildObject();
        statement.setAuthenticationInstant(loginContext.getAuthenticationInstant());
        statement.setAuthenticationMethod(loginContext.getAuthenticationMethod());

        statement.setSubjectLocality(buildSubjectLocality(requestContext));

        Subject statementSubject;
        Endpoint endpoint = selectEndpoint(requestContext);
        if (endpoint.getBinding().equals(SAMLConstants.SAML1_ARTIFACT_BINDING_URI)) {
            statementSubject = buildSubject(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:artifact");
        } else {
            statementSubject = buildSubject(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:bearer");
        }
        statement.setSubject(statementSubject);

        return statement;
    }
    
    /**
     * Constructs the subject locality for the authentication statement.
     * 
     * @param requestContext current request context
     * 
     * @return subject locality for the authentication statement
     */
    protected SubjectLocality buildSubjectLocality(WSFedRequestContext requestContext) {
        SubjectLocality subjectLocality = subjectLocalityBuilder.buildObject();

        HTTPInTransport inTransport = (HTTPInTransport) requestContext.getInboundMessageTransport();
        subjectLocality.setIPAddress(inTransport.getPeerAddress());

        return subjectLocality;
    }

    /**
     * Creates an authentication request context from the current environmental information.
     * 
     * @param loginContext current login context
     * @param in inbound transport
     * @param out outbount transport
     * 
     * @return created authentication request context
     * 
     * @throws ProfileException thrown if there is a problem creating the context
     */
    protected WSFedRequestContext buildRequestContext(WSFedLoginContext loginContext,
            HTTPInTransport in, HTTPOutTransport out) throws ProfileException {
    	WSFedRequestContext requestContext = new WSFedRequestContext();
        requestContext.setCommunicationProfileId(getProfileId());

        requestContext.setMessageDecoder(getInboundMessageDecoder(requestContext));

        requestContext.setLoginContext(loginContext);
        requestContext.setRelayState(loginContext.getSpTarget());

        requestContext.setInboundMessageTransport(in);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        requestContext.setOutboundMessageTransport(out);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        requestContext.setMetadataProvider(getMetadataProvider());

        String relyingPartyId = loginContext.getRelyingPartyId();
        requestContext.setPeerEntityId(relyingPartyId);
        requestContext.setInboundMessageIssuer(relyingPartyId);

        populateRequestContext(requestContext);

        return requestContext;
    }
    
    /** Represents the internal state of a WSFed Request while it's being processed by the IdP. */
    public class WSFedRequestContext extends
            BaseSAML1ProfileRequestContext<Request, Response, WSFedConfiguration> {

        /** SP-provide assertion consumer service URL. */
        private String spAssertionConsumerService;

        /** Current login context. */
        private WSFedLoginContext loginContext;

        /**
         * Gets the current login context.
         * 
         * @return current login context
         */
        public WSFedLoginContext getLoginContext() {
            return loginContext;
        }

        /**
         * Sets the current login context.
         * 
         * @param context current login context
         */
        public void setLoginContext(WSFedLoginContext context) {
            loginContext = context;
        }

        /**
         * Gets the SP-provided assertion consumer service URL.
         * 
         * @return SP-provided assertion consumer service URL
         */
        public String getSpAssertionConsumerService() {
            return spAssertionConsumerService;
        }

        /**
         * Sets the SP-provided assertion consumer service URL.
         * 
         * @param acs SP-provided assertion consumer service URL
         */
        public void setSpAssertionConsumerService(String acs) {
            spAssertionConsumerService = acs;
        }
    }

    @Override
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        	return null;
		// TODO Auto-generated method stub
    }

    @Override
	protected void populateSAMLMessageInformation(
			BaseSAMLProfileRequestContext requestContext)
			throws ProfileException {
		// TODO Auto-generated method stub
		
	}
    
    protected Element buildResponse (WSFedRequest request) throws ProfileException {

        ParserPool pp = new BasicParserPool();
        try {

            // Document doc = pp.newDocument();
            Document doc = request.assertion.getDOM().getOwnerDocument();

            // Build the SOAP envelope and body for the response.
            Element env = doc.createElementNS(XMLNS_SOAP12, "soap:Envelope");
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:soap", XMLNS_SOAP12);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:ic", XMLNS_IC);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wsa", XMLNS_WSA);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wst", XMLNS_WST);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wsse", XMLNS_WSSE);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wsu", XMLNS_WSU);

            if (doc.getDocumentElement()==null)
                doc.appendChild(env);
            else
                doc.replaceChild(env, doc.getDocumentElement());


            /* build header */
            Element hdr = doc.createElementNS(XMLNS_SOAP12, "soap:Header");
            Element sec = doc.createElementNS(XMLNS_WSSE, "wsse:Security");
            sec.setAttribute("soap:mustUnderstand", "1");
            Element ts = doc.createElementNS(XMLNS_WSU, "wsu:Timestamp");
            ts.setAttribute("wsu:Id", "_6");
            // add the create time
            Element ct = doc.createElementNS(XMLNS_WSU, "wsu:Created");
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
            // Calendar cal = Calendar.getInstance();
            // Date now = cal.getTime();
            Date now = new Date();
            ct.appendChild(doc.createTextNode(sdf.format(now)));
           log.debug(" .. created: " + sdf.format(now));
            ts.appendChild(ct);
            Element et = doc.createElementNS(XMLNS_WSU, "wsu:Expires");

            now.setTime(now.getTime()+10*60*1000);  // plus 10 min
            et.appendChild(doc.createTextNode(sdf.format(now)));
           log.debug(" .. expires: " + sdf.format(now));
            ts.appendChild(et);
            sec.appendChild(ts);
            hdr.appendChild(sec);

            env.appendChild(hdr);


            Element body = doc.createElementNS(XMLNS_SOAP12, "soap:Body");
            Element rstr = doc.createElementNS(XMLNS_WST, "wst:RequestSecurityTokenResponse");
            rstr.setAttribute("Context", "ProcessRequestSecurityToken");

            Element tt = doc.createElementNS(XMLNS_WST, "wst:TokenType");
            tt.appendChild(doc.createTextNode(SAMLConstants.SAML1_NS));
            rstr.appendChild(tt);

            Element rt = doc.createElementNS(XMLNS_WST, "wst:RequestType");
            rt.appendChild(doc.createTextNode("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"));
            rstr.appendChild(rt);

            Element rst = doc.createElementNS(XMLNS_WST, "wst:RequestedSecurityToken");

            rst.appendChild(request.assertion.getDOM());

            log.debug("pre-encrypted assertion: " + XMLHelper.nodeToString(XMLHelper.getFirstChildElement(rst)));

            // Check for need to encrypt assertion

            if (request.realRelyingParty != null) {
               Element toe = XMLHelper.getFirstChildElement(rst);
               if (toe!=null) {
                  log.debug(" .. encrypting response");
                  ElementEncrypter ee = new ElementEncrypter();
                  if (realRPCert!=null) {
                      log.debug(".. using cert from request identity for " + request.realRelyingParty);
                      ee.setRPCert((Certificate)realRPCert);
                  } else {
                     Certificate crt = getEncryptionCertificate(request.realRelyingParty);
                     if (crt!=null) {
                        log.debug(".. using cert from metadata for " + request.realRelyingParty);
                        ee.setRPCert(crt);
                     } else {
                        log.debug(".. need to find cert for " + request.realRelyingParty);
                        ee.findRPCert(request.realRelyingParty);
                     }
                  }
                  ee.encryptElement(toe);
               } else {
                  log.error(" .. could not find Assertion");
               }
            }

            rstr.appendChild(rst);

        // add the attach references

            Element rar = doc.createElementNS(XMLNS_WST, "wst:RequestedAttachedReference");
            Element str = doc.createElementNS(XMLNS_WSSE, "wsse:SecurityTokenReference");
            Element kid = doc.createElementNS(XMLNS_WSSE, "wsse:KeyIdentifier");
            kid.setAttribute("ValueType", SAML_ASSERTIONID);
            kid.appendChild(doc.createTextNode("uuid:362397b6-e5f3-4764-b50b-1bb92812ce80"));

            str.appendChild(kid);
            rar.appendChild(str);
            rstr.appendChild(rar);

        // add the unattach references

            rar = doc.createElementNS(XMLNS_WST, "wst:RequestedUnattachedReference");
            str = doc.createElementNS(XMLNS_WSSE, "wsse:SecurityTokenReference");
            kid = doc.createElementNS(XMLNS_WSSE, "wsse:KeyIdentifier");
            kid.setAttribute("ValueType", SAML_ASSERTIONID);
            kid.appendChild(doc.createTextNode("uuid:362397b6-e5f3-4764-b50b-1bb92812ce80"));

            str.appendChild(kid);
            rar.appendChild(str);
            rstr.appendChild(rar);

        // add the display values

            Element rdt = doc.createElementNS(XMLNS_IC, "ic:RequestedDisplayToken");
            Element dt = doc.createElementNS(XMLNS_IC, "ic:DisplayToken");
            dt.setAttribute("xml:lang", "en-us");


            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(request.relyingPartyID);
            WSFedConfiguration cardProfileConfig = (WSFedConfiguration) rpConfig
                .getProfileConfiguration(WSFedConfiguration.PROFILE_ID);

            Map<String, WSFedClaim> cardClaims = cardProfileConfig.getSupportedClaims();
           

            rdt.appendChild(dt);
            rstr.appendChild(rdt);

            body.appendChild(rstr);
            env.appendChild(body);
            return (env);

          } catch (Exception e) {
              throw new ProfileException("sendResponse error:" +  e);
          }
       }
    
    /* Certificate helper. Gets RP cert from metadata if possible.  */
    private Certificate getEncryptionCertificate(String realRelyingParty)
    {
        try {
            MetadataProvider metadataProvider = getMetadataProvider();
            EntityDescriptor entityDescriptor = metadataProvider.getEntityDescriptor(realRelyingParty);
            if (entityDescriptor != null) {
                SPSSODescriptor spDescriptor = null;
                spDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML11P_NS);                
                if (spDescriptor != null) {
                    List<KeyDescriptor> keyDescriptors = spDescriptor.getKeyDescriptors();
                    KeyDescriptor keyDescriptor = keyDescriptors.get(0);
                    KeyInfo keyInfo = keyDescriptor.getKeyInfo();
                    List<X509Certificate> x509Cert  = KeyInfoHelper.getCertificates(keyInfo);
                    return ((Certificate)(x509Cert.get(0)));
                }
            }
        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for relying party: " + e);
        } catch (CertificateException e) {
            log.error("Unable to get cert from keyinfo for relying party: " + e);
        } catch (Exception e) {
            log.error("Unable to get cert from metadata for relying party: " + e);
        }
        return (null);
    }


}