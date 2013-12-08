package au.com.identityconcepts.shibboleth.wsfed.config.profile;
import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
 
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import org.w3c.dom.Element;

import au.com.identityconcepts.shibboleth.wsfed.profile.WSFedProfileHandler;
import edu.internet2.middleware.shibboleth.common.config.profile.AbstractShibbolethProfileHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;
 
public class WSFedHandlerBeanDefinitionParser extends AbstractShibbolethProfileHandlerBeanDefinitionParser {
 
    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(WSFedNamespaceHandler.NAMESPACE, "WSFedPassiveRequestorProfile");
 
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedHandlerBeanDefinitionParser.class);
 
    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return WSFedProfileHandler.class;
    }
 
    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder); 
        
        builder.addConstructorArg(DatatypeHelper.safeTrimOrNullString(config.getAttributeNS(null,
                "authenticationManagerPath")));
        builder.addConstructorArg(DatatypeHelper.safeTrimOrNullString(config.getAttributeNS(null,
                "relyingParty")));
    }
    
    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}