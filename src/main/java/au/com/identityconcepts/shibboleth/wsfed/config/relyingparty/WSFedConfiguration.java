package au.com.identityconcepts.shibboleth.wsfed.config.relyingparty;

import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;

/**
 * WSFed STS saml1 configuration settings.
 */
public class WSFedConfiguration extends AbstractSAML1ProfileConfiguration {

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "wsfed:PassiveRequstorProfile";

    /** {@inheritDoc} */
    public String getProfileId() {
        return PROFILE_ID;
    }

}
