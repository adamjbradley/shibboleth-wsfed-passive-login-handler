package au.com.identityconcepts.shibboleth.wsfed.config.profile;
import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
 
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import org.w3c.dom.Element;

import au.com.identityconcepts.shibboleth.wsfed.profile.WSFedActiveHandler;
import au.com.identityconcepts.shibboleth.wsfed.profile.WSFedProfileHandlerStub;
import edu.internet2.middleware.shibboleth.common.config.profile.AbstractShibbolethProfileHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;
 
public class WSFedActiveHandlerBeanDefinitionParser extends AbstractShibbolethProfileHandlerBeanDefinitionParser {
 
    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(WSFedNamespaceHandler.NAMESPACE, "WSFedActive");
 
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedActiveHandlerBeanDefinitionParser.class);
 
    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return WSFedActiveHandler.class;
    }
 
    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);        
    }
    
    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}