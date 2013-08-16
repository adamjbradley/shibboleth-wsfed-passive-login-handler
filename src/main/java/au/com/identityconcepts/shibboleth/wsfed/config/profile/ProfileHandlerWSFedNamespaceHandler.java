package au.com.identityconcepts.shibboleth.wsfed.config.profile;
 
import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

import au.com.identityconcepts.shibboleth.wsfed.config.profile.authn.WSFedHandlerBeanDefinitionParser;


public class ProfileHandlerWSFedNamespaceHandler extends BaseSpringNamespaceHandler {
 
     /** Namespace URI. */
    public static final String NAMESPACE = "http://www.identityconcepts.com.au/idc/idp/wsfed";
 
    public void init(){
    	registerBeanDefinitionParser(WSFedHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new WSFedHandlerBeanDefinitionParser());
    }
}