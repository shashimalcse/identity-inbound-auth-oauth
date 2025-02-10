/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.api;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_MAIL_LINK;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_MAIL_TEMPLATE_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_USER_AUTH_ENDPOINT_PATH;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * Provides authentication services.
 */
public class CibaAuthServiceImpl implements CibaAuthService {

    private static Log log = LogFactory.getLog(CibaAuthServiceImpl.class);

    @Override
    public CibaAuthCodeResponse generateAuthCodeResponse(CibaAuthCodeRequest cibaAuthCodeRequest)
            throws CibaCoreException, CibaClientException {

        CibaAuthCodeDO cibaAuthCodeDO = generateCibaAuthCodeDO(cibaAuthCodeRequest);
        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistCibaAuthCode(cibaAuthCodeDO);
        return buildAuthCodeResponse(cibaAuthCodeRequest, cibaAuthCodeDO);
    }

    @Override
    public void triggerNotification(String authCodeKey, String bindingMessage, AuthenticatedUser user)
            throws CibaCoreException {

        try {
            ServiceURLBuilder url = ServiceURLBuilder.create().addPath(CIBA_USER_AUTH_ENDPOINT_PATH);
            url.addParameter("authCodeKey", authCodeKey);
            url.addParameter("binding_message", bindingMessage);
            url.addParameter("login_hint", user.toFullQualifiedUsername());
            HashMap<String, Object> properties = new HashMap<>();
            IdentityEventService eventService = CibaServiceComponentHolder.getInstance().getIdentityEventService();

            String email = resolveEmailOfAuthenticatedUser(user);
            properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
            properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
            properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
            properties.put(CIBA_MAIL_LINK, url.build().getAbsoluteInternalURL());
            properties.put("TEMPLATE_TYPE", CIBA_MAIL_TEMPLATE_NAME);
            properties.put("send-to", email);

            Event event = new Event(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, properties);
            try {
                if (eventService != null) {
                    eventService.handleEvent(event);
                }
            } catch (IdentityEventException e) {
                throw new IdentityOAuth2Exception("Authentication Failed! " + e.getMessage(), e);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new CibaCoreException("Error in triggering the notification event", e);
        } catch (URLBuilderException e) {
            throw new CibaCoreException("Error in building the URL for the notification event", e);
        }
    }

    private String resolveEmailOfAuthenticatedUser(AuthenticatedUser user)
            throws CibaCoreException {

        return getUserClaimValueFromUserStore("http://wso2.org/claims/emailaddress", user);
    }

    /**
     * Get user claim value.
     *
     * @param claimUri          Claim uri.
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws CibaCoreException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(String claimUri, AuthenticatedUser authenticatedUser)
            throws CibaCoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUri,
                            "http://wso2.org/claims/identity/preferredChannel"}, null);
            return claimValues.get(claimUri);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error", e);
        }
    }

    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws CibaCoreException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userstoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw new CibaCoreException("User Store Manager is null for the user: " + username);
            }
            if (StringUtils.isBlank(userstoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userstoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userstoreDomain);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error in getting the user store manager for the user: " + username, e);
        }
    }

    private UserRealm getTenantUserRealm(String tenantDomain)
            throws CibaCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (CibaServiceComponentHolder.getInstance().getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error in getting the user realm for the tenant: " + tenantDomain, e);
        }
        if (userRealm == null) {
            throw new CibaCoreException("User Realm is null for the tenant: " + tenantDomain);
        }
        return userRealm;
    }

    /**
     * Returns a unique AuthCodeKey.
     *
     * @return String Returns random uuid.
     */
    private String generateAuthCodeKey() {

        return UUID.randomUUID().toString();
    }

    /**
     * Returns a unique auth_req_id.
     *
     * @return String Returns random uuid.
     */
    private String generateAuthRequestId() {

        return UUID.randomUUID().toString();
    }

    /**
     * Process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthCodeRequest Accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth_req_id.
     */
    private long getExpiresIn(CibaAuthCodeRequest cibaAuthCodeRequest) {

        long requestedExpiry = cibaAuthCodeRequest.getRequestedExpiry();
        if (requestedExpiry == 0) {
            return CibaConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;
        } else if (requestedExpiry < CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC) {
            return requestedExpiry;
        }
        if (log.isDebugEnabled()) {
            log.debug("The requested_expiry: " + requestedExpiry + " exceeds default maximum value: " +
                    CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC + " for the CIBA authentication request made " +
                    "by: " + cibaAuthCodeRequest.getIssuer());
        }
        return CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC;
    }

    /**
     * Builds and returns Ciba AuthCode DO.
     *
     * @param cibaAuthCodeRequest CIBA Request Data Transfer Object.
     * @return CibaAuthCodeDO.
     */
    private CibaAuthCodeDO generateCibaAuthCodeDO(CibaAuthCodeRequest cibaAuthCodeRequest) {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        long expiryTime = getExpiresIn(cibaAuthCodeRequest);
        String[] scopes = cibaAuthCodeRequest.getScopes();
        cibaAuthCodeDO.setCibaAuthCodeKey(this.generateAuthCodeKey());
        cibaAuthCodeDO.setAuthReqId(this.generateAuthRequestId());
        cibaAuthCodeDO.setConsumerKey(cibaAuthCodeRequest.getIssuer());
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setLastPolledTime(issuedTime); // Initially last polled time is set to issued time.
        cibaAuthCodeDO.setAuthReqStatus(AuthReqStatus.REQUESTED);
        cibaAuthCodeDO.setInterval(CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);
        cibaAuthCodeDO.setExpiresIn(expiryTime);
        cibaAuthCodeDO.setScopes(scopes);

        return cibaAuthCodeDO;
    }

    /**
     * Builds and returns CibaAuthCodeResponse.
     *
     * @param cibaAuthCodeDO      DO with information regarding authenticationRequest.
     * @param cibaAuthCodeRequest Auth Code request object.
     * @throws CibaCoreException   Exception thrown from CibaCore Component.
     * @throws CibaClientException Client exception thrown from CibaCore Component.
     */
    private CibaAuthCodeResponse buildAuthCodeResponse(CibaAuthCodeRequest cibaAuthCodeRequest,
                                                       CibaAuthCodeDO cibaAuthCodeDO)
            throws CibaCoreException, CibaClientException {

        String clientID = cibaAuthCodeRequest.getIssuer();
        try {
            CibaAuthCodeResponse cibaAuthCodeResponse = new CibaAuthCodeResponse();
            String user = cibaAuthCodeRequest.getUserHint();
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
            String callbackUri = appDO.getCallbackUrl();
            cibaAuthCodeResponse.setAuthReqId(cibaAuthCodeDO.getAuthReqId());
            cibaAuthCodeResponse.setCallBackUrl(callbackUri);
            cibaAuthCodeResponse.setUserHint(user);
            cibaAuthCodeResponse.setClientId(clientID);
            cibaAuthCodeResponse.setScopes(cibaAuthCodeRequest.getScopes());
            cibaAuthCodeResponse.setExpiresIn(cibaAuthCodeDO.getExpiresIn());
            cibaAuthCodeResponse.setAuthCodeKey(cibaAuthCodeDO.getCibaAuthCodeKey());

            if (StringUtils.isNotBlank(cibaAuthCodeRequest.getBindingMessage())) {
                cibaAuthCodeResponse.setBindingMessage(cibaAuthCodeRequest.getBindingMessage());
            }
            if (StringUtils.isNotBlank(cibaAuthCodeRequest.getTransactionContext())) {
                cibaAuthCodeResponse.setTransactionDetails(cibaAuthCodeRequest.getTransactionContext());
            }
            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthCodeResponse for the client: " + clientID);
            }
            return cibaAuthCodeResponse;
        } catch (IdentityOAuth2Exception e) {
            throw new CibaCoreException("Error in creating AuthCodeResponse for the client: " + clientID, e);
        } catch (InvalidOAuthClientException e) {
            throw new CibaClientException("Error in creating AuthCodeResponse for the client: " + clientID, e);
        }
    }
}
