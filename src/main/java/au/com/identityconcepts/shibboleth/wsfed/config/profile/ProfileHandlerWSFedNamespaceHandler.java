package au.com.identityconcepts.shibboleth.wsfed.config.profile;
 
import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;
import au.com.identityconcepts.shibboleth.wsfed.profile.WSFedHandlerBeanDefinitionParser;


public class ProfileHandlerWSFedNamespaceHandler extends BaseSpringNamespaceHandler {
 
     /** Namespace URI. */
    public static final String NAMESPACE = "au:com:identityconcepts:shibboleth:wsfed";
 
    public void init(){
    	registerBeanDefinitionParser(WSFedHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new WSFedHandlerBeanDefinitionParser());
    }
}