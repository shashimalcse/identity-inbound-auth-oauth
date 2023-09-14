package org.wso2.carbon.identity.oauth.scope.validator.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.role.mgt.ApplicationRoleManager;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;


/**
 * Data holder for Application Role Based Scope Validator.
 */
public class ApplicationRoleBasedScopeValidatorDataHolder {

    private OAuthAdminServiceImpl oAuthAdminServiceImpl;
    private OrganizationManager organizationManager;
    private ApplicationManagementService applicationManagementService;
    private OrganizationUserResidentResolverService organizationUserResidentResolverService;
    private ApplicationRoleManager applicationRoleManager;
    private static ApplicationRoleBasedScopeValidatorDataHolder instance =
            new ApplicationRoleBasedScopeValidatorDataHolder();

    /**
     * Get ApplicationRoleBasedScopeValidatorDataHolder instance.
     *
     * @return ApplicationRoleBasedScopeValidatorDataHolder instance.
     */
    public static ApplicationRoleBasedScopeValidatorDataHolder getInstance() {

        return instance;
    }


    /**
     * Get OAuthAdminServiceImpl instance.
     *
     * @return OAuthAdminServiceImpl instance.
     */
    public OAuthAdminServiceImpl getOAuthAdminServiceImpl() {

        return oAuthAdminServiceImpl;
    }

    /**
     * Set OAuthAdminServiceImpl instance.
     *
     * @param oAuthAdminServiceImpl OAuthAdminServiceImpl instance.
     */
    public void setOAuthAdminServiceImpl(OAuthAdminServiceImpl oAuthAdminServiceImpl) {

        this.oAuthAdminServiceImpl = oAuthAdminServiceImpl;
    }

    /*
     * Get OrganizationManager instance.
     *
     * @return OrganizationManager instance.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set OrganizationManager instance.
     *
     * @param organizationManager OrganizationManager instance.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    /**
     * Get ApplicationManagementService instance.
     *
     * @return ApplicationManagementService instance.
     */
    public ApplicationManagementService getApplicationManagementService() {

        return applicationManagementService;
    }

    /**
     * Set ApplicationManagementService instance.
     *
     * @param applicationManagementService ApplicationManagementService instance.
     */
    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        this.applicationManagementService = applicationManagementService;
    }

    /**
     * Set OrganizationUserResidentResolverService instance.
     *
     * @param organizationUserResidentResolverService OrganizationUserResidentResolverService instance.
     */
    public void setOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        this.organizationUserResidentResolverService = organizationUserResidentResolverService;
    }

    /**
     * Get OrganizationUserResidentResolverService instance.
     *
     * @return OrganizationUserResidentResolverService instance.
     */
    public OrganizationUserResidentResolverService getOrganizationUserResidentResolverService() {

        return organizationUserResidentResolverService;
    }

    /**
     * Set application role management service.
     *
     * @param applicationRoleManager ApplicationRoleManager.
     */
    public void setApplicationRoleManager(ApplicationRoleManager applicationRoleManager) {

        this.applicationRoleManager = applicationRoleManager;
    }

    /**
     * Get role management service.
     *
     * @return RoleManagementService.
     */
    public ApplicationRoleManager getApplicationRoleManager() {

        return applicationRoleManager;
    }
}
