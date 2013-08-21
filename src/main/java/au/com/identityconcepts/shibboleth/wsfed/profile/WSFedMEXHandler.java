package au.com.identityconcepts.shibboleth.wsfed.profile;

import java.io.IOException;
import java.io.OutputStreamWriter;

import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractRequestURIMappedProfileHandler;

/**
 * A simple profile handler that returns the string "ok" if the IdP is able to answer the request. This may be used for
 * very basic monitoring of the IdP.
 * 
 * @deprecated
 */
public class WSFedMEXHandler extends AbstractRequestURIMappedProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedMEXHandler.class);

    /** {@inheritDoc} */
    public void processRequest(InTransport in, OutTransport out) {
        log.warn("This profile handler has been deprecated, use the Status servlet usually located at '/idp/wsfed/status'");
        try {
            OutputStreamWriter writer = new OutputStreamWriter(out.getOutgoingStream());
            writer.write("ok");
            writer.flush();
        } catch (IOException e) {
            log.error("Unable to write response", e);
        }
    }
}