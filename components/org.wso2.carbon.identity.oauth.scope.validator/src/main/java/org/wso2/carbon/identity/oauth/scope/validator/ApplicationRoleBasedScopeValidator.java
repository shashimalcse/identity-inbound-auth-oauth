package org.wso2.carbon.identity.oauth.scope.validator;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.role.mgt.exceptions.ApplicationRoleManagementException;
import org.wso2.carbon.identity.application.role.mgt.model.ApplicationRole;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.scope.validator.exceptions.AppRoleBasedScopeValidatorException;
import org.wso2.carbon.identity.oauth.scope.validator.internal.ApplicationRoleBasedScopeValidatorDataHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.NotImplementedException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth.scope.validator.constants.Constants.CLIENT_TYPE;

/**
 * Application RoleBasedScopeValidator which is used to validate scopes.
 */
public class ApplicationRoleBasedScopeValidator implements ScopeValidator {

    private static final Log LOG = LogFactory.getLog(ApplicationRoleBasedScopeValidator.class);

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {

        // Todo: check whether application role based scope validator is enabled, if not skip the validation.

        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();

        // Todo:  check whether scope validator enable for the client, if not skip the scope validation.

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started scope validation with application role based scope validator in the authorize flow.");
        }

        if (isScopesEmpty(authzReqMessageContext.getAuthorizationReqDTO().getScopes())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested scope list is empty. Therefore, Application role based scope validation with " +
                        "client: " + clientId + " is skipped.");
            }
            authzReqMessageContext.setApprovedScope(new String[0]);
            return true;
        }

        // Get user requested scopes list.
        List<String> requestedScopes = Arrays.asList(authzReqMessageContext.getAuthorizationReqDTO().getScopes());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Requested scopes for scope validation: " + StringUtils.join(requestedScopes, " ")
                    + " by the application: " + clientId);
        }
        String tenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();

        String[] allowedScopes = getAuthorizedScopes(requestedScopes, clientId, tenantDomain,
                authzReqMessageContext.getAuthorizationReqDTO().getUser());
        authzReqMessageContext.setApprovedScope(allowedScopes);
        return true;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        // Todo: check whether application role based scope validator is enabled, if not skip the validation.

        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();

        // Todo:  check whether scope validator enable for the client, if not skip the scope validation.

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started scope validation with application role based scope validator in the authorize flow.");
        }

        if (isScopesEmpty(tokenReqMessageContext.getScope())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested scope list is empty. Therefore, Application role base scope validation with " +
                        "client: " + clientId + " is skipped.");
            }
            tokenReqMessageContext.setScope(new String[0]);
            return true;
        }

        // Get user requested scopes list.
        List<String> requestedScopes = Arrays.asList(tokenReqMessageContext.getScope());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Requested scopes for scope validation: " + StringUtils.join(requestedScopes, " ")
                    + " by the application: " + clientId);
        }
        String tenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        String[] allowedScopes;
        AuthenticatedUser authorizedUser = tokenReqMessageContext.getAuthorizedUser();
        allowedScopes = getAuthorizedScopes(requestedScopes, clientId, tenantDomain, authorizedUser);
        tokenReqMessageContext.setScope(allowedScopes);
        return true;
    }

    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext tokenValidationMessageContext)
            throws IdentityOAuth2Exception {

        return true;
    }

    @Override
    public String getName() {

        return "Application Role Based Scope Validator";
    }

    private String[] getAuthorizedScopes(List<String> requestedScopes, String clientId, String tenantDomain,
                                         AuthenticatedUser user)
            throws IdentityOAuth2Exception {

        // Filter OIDC scopes and add to approved scopes list.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Filtering OIDC scopes from requested scopes: " + StringUtils.join(requestedScopes, " "));
        }
        Set<String> requestedOIDCScopes = getRequestedOIDCScopes(tenantDomain, requestedScopes);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Requested OIDC scopes : " + StringUtils.join(requestedOIDCScopes, " "));
        }
        /* Here, we add the user-requested OIDC scopes to the approved scope list and remove from requested scope list
        before we pass the scopes to the authorization service. Otherwise, the OIDC scopes will be dropped from
        the approved scope list. */
        List<String> approvedScopes = new ArrayList<>(requestedOIDCScopes);
        requestedScopes = removeOIDCScopes(requestedScopes, requestedOIDCScopes);

        if (!requestedScopes.isEmpty()) {
            String appId = getApplicationId(clientId, tenantDomain);
            List<String> allowedScopes;
            List<String> applicationRoles;
            try {
                applicationRoles = getApplicationRoles(user, appId);
            } catch (AppRoleBasedScopeValidatorException e) {
                throw new IdentityOAuth2Exception("Error while getting application roles", e);
            }
            try {
                allowedScopes = getAuthorizedScopesFromRoles(requestedScopes, applicationRoles, tenantDomain);
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Error while validating scopes from authorization service.", e);
                }
                throw new IdentityOAuth2Exception("Error validating scopes from authorization service.", e);
            }
            approvedScopes.addAll(allowedScopes);
            LOG.debug("Completed scope validation with application role based scope validator.");
            return approvedScopes.toArray(new String[0]);
        }
        return approvedScopes.toArray(new String[0]);
    }

    private List<String> getUserGroups(AuthenticatedUser authenticatedUser, String userResidentTenantDomain)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started group fetching for scope validation.");
        }
        List<String> userGroups = new ArrayList<>();
        if (authenticatedUser.isFederatedUser()) {
            return userGroups;
        }
        RealmService realmService = UserCoreUtil.getRealmService();
        try {
            int tenantId = OAuth2Util.getTenantId(userResidentTenantDomain);
            UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            List<Group> groups =
                    ((AbstractUserStoreManager) userStoreManager).getGroupListOfUser(authenticatedUser.getUserId(),
                            null, null);
            // Exclude internal and application groups from the list.
            for (Group group : groups) {
                userGroups.add(group.getGroupID());
            }
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        } catch (UserStoreException e) {
            if (isDoGetGroupListOfUserNotImplemented(e)) {
                return userGroups;
            }
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        return userGroups;
    }

    private Set<String> getRequestedOIDCScopes(String tenantDomain, List<String> requestedScopes)
            throws IdentityOAuth2Exception {

        OAuthAdminServiceImpl oAuthAdminServiceImpl =
                ApplicationRoleBasedScopeValidatorDataHolder.getInstance().getOAuthAdminServiceImpl();
        if (oAuthAdminServiceImpl == null) {
            throw new IdentityOAuth2Exception("Error while retrieving OIDC scopes.");
        }

        try {
            List<String> oidcScopes = oAuthAdminServiceImpl.getRegisteredOIDCScope(tenantDomain);
            return requestedScopes.stream().distinct().filter(oidcScopes::contains).collect(Collectors.toSet());
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityOAuth2Exception("Error while getting OIDC Scopes for tenant : " + tenantDomain, e);
        }
    }

    private List<String> removeOIDCScopes(List<String> requestedScopes, Set<String> oidcScopes) {

        return requestedScopes.stream().distinct().filter(s -> !oidcScopes.contains(s)).collect(Collectors.toList());
    }

    private List<String> getApplicationRoles(AuthenticatedUser authenticatedUser, String appId)
            throws AppRoleBasedScopeValidatorException {

        String tenantDomain = authenticatedUser.getTenantDomain();
        String userID;
        try {
            userID = authenticatedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            throw new AppRoleBasedScopeValidatorException("Error while getting user id", e);
        }
        if (StringUtils.isBlank(userID)) {
            throw new AppRoleBasedScopeValidatorException("User id not found");
        }
        // Get normal user app roles:
        List<ApplicationRole> appRoles = new ArrayList<>();
        try {
            List<ApplicationRole> appRolesByUser = ApplicationRoleBasedScopeValidatorDataHolder.getInstance()
                    .getApplicationRoleManager().getApplicationRolesByUserId(userID, appId, tenantDomain);
            appRoles.addAll(appRolesByUser);
        } catch (ApplicationRoleManagementException e) {
            throw new AppRoleBasedScopeValidatorException("Error while getting application role for user id : "
                    + userID + " app id : " + appId, e);
        }
        List<String> groups;
        try {
            groups = getUserGroups(authenticatedUser, authenticatedUser.getTenantDomain());
        } catch (IdentityOAuth2Exception e) {
            throw new AppRoleBasedScopeValidatorException("Error while getting user groups", e);
        }
        if (groups.isEmpty()) {
            return appRoles.stream().map(ApplicationRole::getRoleId).collect(Collectors.toList());
        }
        try {
            List<ApplicationRole> appRolesByGroups = ApplicationRoleBasedScopeValidatorDataHolder.getInstance()
                    .getApplicationRoleManager().getApplicationRolesByGroupIds(groups, appId, tenantDomain);
            appRoles.addAll(appRolesByGroups);
        } catch (ApplicationRoleManagementException e) {
            throw new AppRoleBasedScopeValidatorException("Error while getting application role for groups with " +
                    "app id : " + appId, e);
        }
        return appRoles.stream().map(ApplicationRole::getRoleId).distinct().collect(Collectors.toList());
    }

    private List<String> getAuthorizedScopesFromRoles(List<String> requestedScopes, List<String> roleIds,
                                                      String tenantDomain)
            throws AppRoleBasedScopeValidatorException {

        List<String> authorizedScopes = new ArrayList<>();
        try {
            List<String> validatedScopes = ApplicationRoleBasedScopeValidatorDataHolder.getInstance()
                    .getApplicationRoleManager().getScopesByRoleIds(roleIds, tenantDomain);
            authorizedScopes.addAll(validatedScopes);
        } catch (ApplicationRoleManagementException e) {
            throw new AppRoleBasedScopeValidatorException("Error while getting authorized scopes roles", e);
        }
        return authorizedScopes.stream().filter(requestedScopes::contains).collect(Collectors.toList());
    }

    private String getApplicationId(String clientId, String tenantName) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationManagementService = ApplicationRoleBasedScopeValidatorDataHolder
                .getInstance().getApplicationManagementService();
        try {
            return applicationManagementService.getApplicationResourceIDByInboundKey(clientId, CLIENT_TYPE, tenantName);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving application resource id for client : " +
                    clientId + " tenant : " + tenantName, e);
        }
    }

    private boolean isScopesEmpty(String[] scopes) {

        return ArrayUtils.isEmpty(scopes);
    }

    private boolean isDoGetGroupListOfUserNotImplemented(UserStoreException e) {

        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof NotImplementedException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }
}
