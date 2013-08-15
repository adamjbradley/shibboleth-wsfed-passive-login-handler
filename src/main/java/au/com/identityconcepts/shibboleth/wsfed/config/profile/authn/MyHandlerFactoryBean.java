package au.com.identityconcepts.shibboleth.wsfed.config.profile.authn;

import au.com.identityconcepts.shibboleth.wsfed.authn.provider.MyloginHandler;

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;
/**
 * Factory bean for {@link MyloginHandler}s.
 */
 
public class MyHandlerFactoryBean extends AbstractLoginHandlerFactoryBean{
 
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
        MyloginHandler handler = new MyloginHandler(authenticationServletURL);
 
        populateHandler(handler);
 
        return handler;
 
    }
 
    @Override
    public Class getObjectType() {
        return MyloginHandler.class;
    }
}