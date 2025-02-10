package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Rest implementation for ciba authentication flow.
 */
@Path("/ciba_auth")
public class UserAuthenticationEndpoint {

    private static final Log
            log = LogFactory.getLog(UserAuthenticationEndpoint.class);
    public static final String ERROR = "error";
    public static final String INVALID_CODE_ERROR_KEY = "invalid.code";
    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();

    @GET
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/html")
    public Response deviceAuthorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws InvalidRequestParentException, OAuthSystemException {

        String authCodeKey = request.getParameter("authCodeKey");
        String loginHint = request.getParameter("binding_message");
        String bindingMessage = request.getParameter("login_hint");
        // True when input(user_code) is not REQUIRED.
        if (StringUtils.isBlank(authCodeKey)) {
            if (log.isDebugEnabled()) {
                log.debug("code is missing in the request.");
            }
            String error = null;
            try {
                error = ServiceURLBuilder.create().addPath(Constants.DEVICE_ENDPOINT_PATH)
                        .addParameter(ERROR, INVALID_CODE_ERROR_KEY).build().getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                throw new RuntimeException(e);
            }
            return Response.status(HttpServletResponse.SC_FOUND).location(URI.create(error)).build();
        }
        try {
            CibaAuthCodeDO cibaAuthCodeDO =
                    CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCode(authCodeKey);;
            CommonAuthRequestWrapper commonAuthRequestWrapper = new CommonAuthRequestWrapper(request);
            commonAuthRequestWrapper.setParameter(
                    org.wso2.carbon.identity.openidconnect.model.Constants.SCOPE,
                    OAuth2Util.buildScopeString(cibaAuthCodeDO.getScopes()));
            commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants.RESPONSE_TYPE,
                    CibaConstants.RESPONSE_TYPE_VALUE);
            commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants.NONCE,
                    cibaAuthCodeDO.getAuthReqId());
            commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants.REDIRECT_URI,
                    "https://oauth.pstmn.io/v1/callback");
            commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants.CLIENT_ID,
                    cibaAuthCodeDO.getConsumerKey());
            commonAuthRequestWrapper.setParameter(CibaConstants.USER_IDENTITY, loginHint);
            commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants.LOGIN_HINT,
                    loginHint);
            if (!StringUtils.isBlank(bindingMessage)) {
                commonAuthRequestWrapper.setParameter(CibaConstants.BINDING_MESSAGE, bindingMessage);
            }
            commonAuthRequestWrapper.setAttribute(OAuthConstants.PKCE_UNSUPPORTED_FLOW, true);
            return oAuth2AuthzEndpoint.authorize(commonAuthRequestWrapper, response);
        } catch (CibaCoreException e) {
            throw new RuntimeException(e);
        } catch (URISyntaxException e) {
            return handleURISyntaxException(e);
        }
    }

    private Response handleURISyntaxException(URISyntaxException e) throws OAuthSystemException {

        log.error("Error while parsing string as an URI reference.", e);
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

}
