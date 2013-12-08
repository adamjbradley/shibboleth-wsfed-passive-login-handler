package au.com.identityconcepts.shibboleth.wsfed.profile;

import au.com.identityconcepts.shibboleth.wsfed.config.relyingparty.WSFedConfiguration;



import java.io.StringReader;
import java.io.Writer;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;


import edu.internet2.middleware.shibboleth.idp.profile.saml1.*;
import edu.internet2.middleware.shibboleth.idp.session.Session;

import org.opensaml.common.SAMLObject;

import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.AbstractSAMLProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.saml1.*;


public class WSFedActiveHandler extends AbstractSAML1ProfileHandler {
	
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedActiveHandler.class);

    /**
     * Constructor.
     * 
     */
    @SuppressWarnings("unchecked")
    public WSFedActiveHandler() {
        super();
    }
    
    /** Initialize the profile handler. */
    public void initialize() {
    }


    /** {@inheritDoc} */
    public String getProfileId() {
        return WSFedConfiguration.PROFILE_ID;
    }
    	
    /**
     * Creates a response to the {@link AuthnRequest} and sends the user, with response in tow, back to the relying
     * party after they've been authenticated.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if the response can not be created and sent back to the relying party
     */
    protected void completeAuthenticationRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();

        WSFedRequestContext requestContext = buildRequestContext(inTransport, outTransport);

        Response samlResponse;

        try {
            //decodeRequest(requestContext, inTransport, outTransport);
            //checkSamlVersion(requestContext);

            String user = httpRequest.getRemoteUser().replaceFirst("@.*","");
            log.debug("Setting principal name: " +user+ " ("+ httpRequest.getRemoteUser()+")");
            requestContext.setPrincipalName(user);

            if (requestContext.getSubjectNameIdentifier() != null) {
                log.debug("Authentication request contained a subject with a name identifier, resolving principal from NameID");
                String authenticatedName = requestContext.getPrincipalName();
                //resolvePrincipal(requestContext);
                String requestedPrincipalName = requestContext.getPrincipalName();
                if (!DatatypeHelper.safeEquals(authenticatedName, requestedPrincipalName)) {
                    log.warn(
                            "Authentication request identified principal {} but authentication mechanism identified principal {}",
                            requestedPrincipalName, authenticatedName);                                        
                    //requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error authenticating"));
                    
                    throw new ProfileException("User failed authentication");
                }
            }

            String relyingPartyId = requestContext.getInboundMessageIssuer();
            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
            ProfileConfiguration wsFedConfig = rpConfig.getProfileConfiguration(getProfileId());
            if (wsFedConfig == null) {
                log.warn("WSFed profile is not configured for relying party '{}'", requestContext.getInboundMessageIssuer());
                throw new ProfileException("WSFed profile is not configured for relying party");
            }

            //resolveAttributes(requestContext);
            
            ArrayList<Statement> statements = new ArrayList<Statement>();
            //statements.add(buildAuthnStatement(requestContext));
            /*
            if (requestContext.getProfileConfiguration().seincludeAttributeStatement()) {
            	AttributeStatement attributeStatement = buildAttributeStatement(requestContext);
                if (attributeStatement != null) {
                    requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());
                    statements.add(attributeStatement);
                }
            }
            */

            samlResponse = buildResponse(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:bearer", statements);
            //samlResponse.setDestination(requestContext.getPeerEntityEndpoint().getLocation());

        } catch (ProfileException e) {

            // send a soap fault
            log.debug("sending soap error: " +  e);
            try {
               String msg = e.getMessage();
               if (msg==null) msg = "";
               outTransport.setCharacterEncoding("UTF-8");
               outTransport.setHeader("Content-Type", "application/soap+xml");
               // outTransport.setStatusCode(500);  // seem to lose the message when we report an error.
               Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
               //out.write(soapFaultResponseMessage.replaceAll("MESSAGE", msg));
               out.flush();
            } catch (Exception we) {
               log.error("error writing soap error: " +  we);
            }
            return;
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        //encodeResponse(requestContext);
        //writeAuditLogEntry(requestContext);
    }

	  
    private Response buildResponse(WSFedRequestContext requestContext,
			String string, ArrayList<Statement> statements) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
     * Creates an authentication request context from the current environmental information.
     * 
     * @param in inbound transport
     * @param out outbount transport
     * 
     * @return created authentication request context
     * 
     * @throws ProfileException thrown if there is a problem creating the context
     */
    protected WSFedRequestContext buildRequestContext(HTTPInTransport in,
            HTTPOutTransport out) throws ProfileException {
    	
        WSFedRequestContext requestContext = new WSFedRequestContext();

        requestContext.setCommunicationProfileId(getProfileId());
        //requestContext.setMessageDecoder(getInboundMessageDecoder(requestContext));
        requestContext.setInboundMessageTransport(in);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML11P_NS);
        requestContext.setOutboundMessageTransport(out);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);
        //requestContext.setMetadataProvider(getMetadataProvider());

        String relyingPartyId = requestContext.getInboundMessageIssuer();
        requestContext.setPeerEntityId(relyingPartyId);
        requestContext.setInboundMessageIssuer(relyingPartyId);
        //requestContext.setOutboundHandlerChainResolver(getOutboundHandlerChainResolver());

        return requestContext;
    }
	
    /** In case we ever add something to the base context **/
    protected class WSFedRequestContext extends BaseSAML1ProfileRequestContext<Request, Response, WSFedConfiguration> {
    }

	@Override
	public void processRequest(HTTPInTransport inTransport,
			HTTPOutTransport outTransport) throws ProfileException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void populateSAMLMessageInformation(
			BaseSAMLProfileRequestContext requestContext)
			throws ProfileException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected Endpoint selectEndpoint(
			BaseSAMLProfileRequestContext requestContext)
			throws ProfileException {
		// TODO Auto-generated method stub
		return null;
	}

}