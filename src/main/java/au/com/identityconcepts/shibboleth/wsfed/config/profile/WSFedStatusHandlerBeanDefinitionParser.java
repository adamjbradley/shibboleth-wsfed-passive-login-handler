package au.com.identityconcepts.shibboleth.wsfed.config.profile;

import au.com.identityconcepts.shibboleth.wsfed.profile.WSFedStatusHandler;
import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.profile.AbstractRequestURIMappedProfileHandlerBeanDefinitionParser;

public class WSFedStatusHandlerBeanDefinitionParser extends AbstractRequestURIMappedProfileHandlerBeanDefinitionParser {
 
	 /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(WSFedNamespaceHandler.NAMESPACE, "WSFedStatus");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedStatusHandlerBeanDefinitionParser.class);
    
    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
    	log.debug("getBeanClass (entering) success");
    	log.debug("getBeanClass (leaving) success");
        return WSFedStatusHandler.class;        
    }

    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}