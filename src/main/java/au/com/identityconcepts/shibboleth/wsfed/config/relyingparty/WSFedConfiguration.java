package au.com.identityconcepts.shibboleth.wsfed.config.relyingparty;

import java.util.HashMap;
import java.util.Map;

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
    
    private Map<String, WSFedClaim> supportedClaims;

    /**
     * Constructor.
     *
     */
    public WSFedConfiguration() {
    	supportedClaims = new HashMap<String, WSFedClaim>();
    }
    
    public Map<String, WSFedClaim> getSupportedClaims() {
        return supportedClaims;
    }
}
