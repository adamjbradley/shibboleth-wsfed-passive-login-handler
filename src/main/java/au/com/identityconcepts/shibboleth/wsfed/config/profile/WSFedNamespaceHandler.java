package au.com.identityconcepts.shibboleth.wsfed.config.profile;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class WSFedNamespaceHandler extends BaseSpringNamespaceHandler {
 
    /** Namespace URI. */
    public static final String NAMESPACE = "au:com:identityconcepts:shibboleth:wsfed";
        					
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedHandlerBeanDefinitionParser.class);

    public void init(){
    	log.debug("init entering (success)");
    	registerBeanDefinitionParser(WSFedHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new WSFedHandlerBeanDefinitionParser());
    	registerBeanDefinitionParser(WSFedActiveHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new WSFedActiveHandlerBeanDefinitionParser());    	
    	registerBeanDefinitionParser(WSFedMEXHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new WSFedMEXHandlerBeanDefinitionParser());    	
    	registerBeanDefinitionParser(WSFedStatusHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new WSFedStatusHandlerBeanDefinitionParser());    	
    	log.debug("init leaving (success)");
    	
    }
}