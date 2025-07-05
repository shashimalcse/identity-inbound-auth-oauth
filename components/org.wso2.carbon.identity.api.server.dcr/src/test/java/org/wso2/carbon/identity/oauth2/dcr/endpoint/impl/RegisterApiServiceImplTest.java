/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dcr.endpoint.impl;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.TestUtil;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ApplicationDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.exceptions.DCRMEndpointException;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.util.DCRMUtils;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class RegisterApiServiceImplTest {

    private RegisterApiServiceImpl registerApiService = null;
    private Application application = null;
    private List<String> redirectUris = new ArrayList<>();

    private String validclientId;

    @Mock
    BundleContext bundleContext;

    @Mock
    private DCRMService dcrmService;

    @Mock
    PrivilegedCarbonContext privilegedCarbonContext;

    MockedConstruction<ServiceTracker> mockedConstruction;
    private MockedStatic<PrivilegedCarbonContext> mockedPrivilegedCarbonContext;

    @BeforeMethod
    public void setUp() throws Exception {

        mockedPrivilegedCarbonContext = mockStatic(PrivilegedCarbonContext.class);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
        lenient().when(PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(DCRMService.class, null)).thenReturn(mock(DCRMService.class));

        //Initializing variables.
        registerApiService = new RegisterApiServiceImpl();
        validclientId = "N2QqQluzQuL5X6CtM3KZwqzLQhUa";
        application = new Application();
        redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
        application.setClientName("Application");
        application.setClientId("N2QqQluzQuL5X6CtM3KZwqzLQhUa");
        application.setClientSecret("4AXWrN88aEfMvq2h_G0dN05KRsUa");
        application.setRedirectUris(redirectUris);

        //Get OSGIservice by starting the tenant flow.
        TestUtil.startTenantFlow("carbon.super");
        Object[] services = new Object[1];
        services[0] = dcrmService;

        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    when(mock.getServices()).thenReturn(services);
                });

        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDown() {

        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
        mockedPrivilegedCarbonContext.close();
    }

    @Test
    public void testDeleteApplication() throws Exception {

        lenient().doNothing().when(dcrmService).deleteApplication(validclientId);
        Assert.assertEquals(registerApiService.deleteApplication(validclientId).getStatus(),
                Response.Status.NO_CONTENT.getStatusCode());
    }

    @Test
    public void testDeleteApplicationServerException() throws Exception {

        lenient().doThrow(new DCRMServerException("Server")).when(dcrmService).deleteApplication(validclientId);
        try {
            registerApiService.deleteApplication(validclientId);
        } catch (DCRMEndpointException e) {
            Assert.assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public void testGetApplication() throws Exception {

        lenient().when(dcrmService.getApplication(validclientId)).thenReturn(application);
        Assert.assertEquals(registerApiService.getApplication(validclientId).getStatus(),
                Response.Status.OK.getStatusCode());

    }

    @Test
    public void testGetApplicationServerException() throws DCRMException {

        lenient().when(dcrmService.getApplication("N2QqQluzQuL5X6CtM3KZwqzLQxxx")).
                thenThrow(new DCRMServerException("This is a server exception"));

        try {
            registerApiService.getApplication("N2QqQluzQuL5X6CtM3KZwqzLQxxx");
        } catch (DCRMEndpointException e) {
            Assert.assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }

    }

    @Test
    public void testRegisterApplication() throws Exception {

        RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
        registrationRequestDTO.setClientName("app1");
        lenient().when(dcrmService.registerApplication(any(ApplicationRegistrationRequest.class)))
                .thenReturn(application);
        Assert.assertEquals(registerApiService.registerApplication(registrationRequestDTO)
                .getStatus(), Response.Status.CREATED.getStatusCode());
    }

    @Test
    public void testRegisterApplicationExcludeNullFieldsTrue() throws Exception {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(OAuthConstants.RETURN_NULL_FIELDS_IN_DCR_RESPONSE))
                    .thenReturn("true");

            RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
            registrationRequestDTO.setClientName("app1");
            lenient().when(dcrmService.registerApplication(any(ApplicationRegistrationRequest.class)))
                    .thenReturn(application);
            Assert.assertEquals(registerApiService.registerApplication(registrationRequestDTO)
                    .getStatus(), Response.Status.CREATED.getStatusCode());
        }
    }

    @Test
    public void testUpdateApplicationServerException() throws Exception {

        UpdateRequestDTO updateRequestDTO = new UpdateRequestDTO();
        lenient().doThrow(new DCRMServerException("Server")).when(dcrmService).updateApplication
                (any(ApplicationUpdateRequest.class), any(String.class));
        try {
            registerApiService.updateApplication(updateRequestDTO, validclientId);
        } catch (DCRMEndpointException e) {
            Assert.assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public void testUpdateApplication() throws Exception {

        UpdateRequestDTO updateRequestDTO1 = new UpdateRequestDTO();
        updateRequestDTO1.setClientName("Client1");
        String clientID = "clientID1";
        lenient().when(dcrmService.updateApplication
                (any(ApplicationUpdateRequest.class), anyString()))
                .thenReturn(application);
        Assert.assertEquals(registerApiService.updateApplication(updateRequestDTO1, clientID)
                .getStatus(), Response.Status.OK.getStatusCode());

    }

    @Test
    public void testGetApplicationByName() throws Exception {

        lenient().when(dcrmService.getApplicationByName("app1")).thenReturn(application);
        Assert.assertEquals(registerApiService.getApplicationByName("app1").getStatus(),
                Response.Status.OK.getStatusCode());
    }

    @Test
    public void testGetApplicationByNameJsonProcessingExceptionCaught() throws Exception {

        Application app = new Application();
        app.setClientId("client123");
        app.setClientName("TestApp");

        // Force an invalid object to cause JSON processing failure (like a circular reference)
        ApplicationDTO dto = new ApplicationDTO() {
            @Override
            public String getClientId() {
                throw new RuntimeException("Force serialization failure");
            }
        };

        lenient().when(dcrmService.getApplicationByName("TestApp")).thenReturn(app);
        try (MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<DCRMUtils> mockedDCRMUtils = mockStatic(DCRMUtils.class)) {

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(OAuthConstants.RETURN_NULL_FIELDS_IN_DCR_RESPONSE))
                    .thenReturn("false");
            mockedDCRMUtils.when(() -> DCRMUtils.getOAuth2DCRMService()).thenReturn(dcrmService);
            mockedDCRMUtils.when(() -> DCRMUtils.getApplicationDTOFromApplication(any())).thenReturn(dto);

            Response response = registerApiService.getApplicationByName("TestApp");

            // Should gracefully handle serialization failure and return 500
            Assert.assertEquals(response.getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }
}
