package au.com.identityconcepts.shibboleth.wsfed.config.profile.authn;
import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
 
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import org.w3c.dom.Element;

import au.com.identityconcepts.shibboleth.wsfed.config.profile.ProfileHandlerWSFedNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;
 
public class WSFedHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {
 
    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "WSFed");
 
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedHandlerBeanDefinitionParser.class);
 
    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return WSFedHandlerFactoryBean.class;
    }
 
    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder); 
        builder.addPropertyValue("authenticationServletURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"authenticationServletURL")));
    }
}