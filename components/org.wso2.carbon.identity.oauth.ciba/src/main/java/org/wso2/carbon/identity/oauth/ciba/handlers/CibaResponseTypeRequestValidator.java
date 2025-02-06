package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.wso2.carbon.identity.oauth2.authz.validators.AbstractResponseTypeRequestValidator;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.RESPONSE_TYPE_VALUE;

/**
 * Validates authorize responses with cibaAuthCode as response type.
 */
public class CibaResponseTypeRequestValidator extends AbstractResponseTypeRequestValidator {

    @Override
    public String getResponseType() {

        return RESPONSE_TYPE_VALUE;
    }
}
