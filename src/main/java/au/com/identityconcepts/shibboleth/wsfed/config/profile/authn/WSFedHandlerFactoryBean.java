package au.com.identityconcepts.shibboleth.wsfed.config.profile.authn;

import au.com.identityconcepts.shibboleth.wsfed.authn.WSFedSTSLoginHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;
/**
 * Factory bean for {@link WSFedSTSLoginHandler}s.
 */
 
public class WSFedHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {
 
    // URL to authentication servlet
    private String authenticationServletURL;
 
    /**
     * Gets the URL to authentication servlet.
     * @return URL to authentication servlet
     */
    public String getAuthenticationServletURL(){
        return authenticationServletURL;
    }
 
    /**
     * Set URL to authentication servlet
     * @param url URL to authentication servlet
     */
    public void setAuthenticationServletURL(String url){
        authenticationServletURL = url;
    }
 
    @Override
    protected Object createInstance() throws Exception {
        WSFedSTSLoginHandler handler = new WSFedSTSLoginHandler(authenticationServletURL); 
        populateHandler(handler);
        return handler; 
    }
 
    @Override
    public Class getObjectType() {
        return WSFedSTSLoginHandler.class;
    }
}