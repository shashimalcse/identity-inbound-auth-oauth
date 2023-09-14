package org.wso2.carbon.identity.oauth.scope.validator.exceptions;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * Exception from Application Role Based Scope Validator.
 */
public class AppRoleBasedScopeValidatorException extends IdentityOAuth2Exception {

    private static final long serialVersionUID = -7175652541752490236L;

    /**
     * Constructor with error message.
     *
     * @param message Error message.
     */
    public AppRoleBasedScopeValidatorException(String message) {

        super(message);
    }

    /**
     * Constructor with error code and error message.
     *
     * @param errorCode Error code.
     * @param message Error message.
     */
    public AppRoleBasedScopeValidatorException(String errorCode, String message) {

        super(errorCode, message);
    }

    public AppRoleBasedScopeValidatorException(String message, Throwable cause) {

        super(message, cause);
    }

}
