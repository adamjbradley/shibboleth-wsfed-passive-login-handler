package au.com.identityconcepts.shibboleth.wsfed.authn.provider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import java.io.IOException;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import org.opensaml.util.URLBuilder;
 
import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
 
public class MyloginHandler extends AbstractLoginHandler {
 
     /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MyloginHandler.class);
 
    /** The URL of the servlet used to perform authentication. */
    private String authenticationServletURL;
 
    /**
     * Constructor.
     *
     * @param servletURL URL to the authentication servlet
     */
    public MyloginHandler(String servletURL) {
        super();
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