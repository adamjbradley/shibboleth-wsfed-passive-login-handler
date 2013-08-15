package au.com.identityconcepts.shibboleth.wsfed.config.profile;
 
import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

import au.com.identityconcepts.shibboleth.wsfed.config.profile.authn.MyHandlerBeanDefinitionParser;


public class ProfileHandlerMyNamespaceHandler extends BaseSpringNamespaceHandler {
 
     /** Namespace URI. */
    public static final String NAMESPACE = "http://example.org/shibboleth/authn";
 
    public void init(){        
        registerBeanDefinitionParser(MyHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new MyHandlerBeanDefinitionParser());
    }
}