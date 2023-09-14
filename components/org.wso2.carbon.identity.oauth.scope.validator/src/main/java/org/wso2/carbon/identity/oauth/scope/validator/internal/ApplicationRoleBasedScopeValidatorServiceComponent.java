package org.wso2.carbon.identity.oauth.scope.validator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.role.mgt.ApplicationRoleManager;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.scope.validator.ApplicationRoleBasedScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;

/**
 * Application Role Based Scope Validator Component.
 */
@Component(
        name = "identity.oauth.scope.validator.component",
        immediate = true
)
public class ApplicationRoleBasedScopeValidatorServiceComponent {

    private static final Log log = LogFactory.getLog(ApplicationRoleBasedScopeValidatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(ScopeValidator.class, new ApplicationRoleBasedScopeValidator(),
                    null);
            if (log.isDebugEnabled()) {
                log.debug("CIBA component bundle is activated.");
            }
        } catch (Throwable e) {
            log.error("Error occurred while activating Scope Validator Component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        log.debug("Application Role Based Scope Validator is deactivated.");
    }

    @Reference(
            name = "OAuthAdminServiceImpl",
            service = OAuthAdminServiceImpl.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOAuthAdminServiceImpl"
    )
    protected void setOAuthAdminServiceImpl(OAuthAdminServiceImpl oAuthAdminServiceImpl) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setOAuthAdminServiceImpl(oAuthAdminServiceImpl);
    }

    protected void unsetOAuthAdminServiceImpl(OAuthAdminServiceImpl oAuthAdminServiceImpl) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setOAuthAdminServiceImpl(null);
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "ApplicationManagementService",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(
            ApplicationManagementService applicationManagementService) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance()
                .setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(
            ApplicationManagementService applicationManagementService) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(
            name = "organization.user.resident.resolver.service",
            service = OrganizationUserResidentResolverService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserResidentResolverService"
    )
    protected void setOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setOrganizationUserResidentResolverService(
                organizationUserResidentResolverService);
    }

    protected void unsetOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setOrganizationUserResidentResolverService(null);
    }

    /**
     * Set application role manager implementation.
     *
     * @param applicationRoleManager ApplicationRoleManager
     */
    @Reference(
            name = "identity.application.role.mgt.component",
            service = org.wso2.carbon.identity.application.role.mgt.ApplicationRoleManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationRoleManager")
    protected void setApplicationRoleManager(ApplicationRoleManager applicationRoleManager) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setApplicationRoleManager(applicationRoleManager);
    }

    /**
     * Unset application role manager implementation.
     */
    protected void unsetApplicationRoleManager(ApplicationRoleManager applicationRoleManager) {

        ApplicationRoleBasedScopeValidatorDataHolder.getInstance().setApplicationRoleManager(null);
    }
}
