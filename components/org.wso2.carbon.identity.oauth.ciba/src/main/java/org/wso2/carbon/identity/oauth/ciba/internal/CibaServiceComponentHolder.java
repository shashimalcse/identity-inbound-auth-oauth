package org.wso2.carbon.identity.oauth.ciba.internal;

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service holder for managing instances of Ciba related services.
 */
public class CibaServiceComponentHolder {

    private static CibaServiceComponentHolder instance = new CibaServiceComponentHolder();
    private static IdentityEventService identityEventService;
    private static RealmService realmService;

    private CibaServiceComponentHolder() {

    }

    public static CibaServiceComponentHolder getInstance() {

        return instance;
    }

    public IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    public void setIdentityEventService(IdentityEventService identityEventService) {

        CibaServiceComponentHolder.identityEventService = identityEventService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        CibaServiceComponentHolder.realmService = realmService;
    }

}
