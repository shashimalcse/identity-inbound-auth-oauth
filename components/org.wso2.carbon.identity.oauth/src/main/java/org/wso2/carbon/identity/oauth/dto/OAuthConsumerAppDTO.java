/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dto;

/**
 * OAuth consumer app dto.
 */
public class OAuthConsumerAppDTO {

    private String oauthConsumerKey;
    private String oauthConsumerSecret;
    private String applicationName;
    private String callbackUrl;
    private String oauthVersion;
    private String username;
    private String grantTypes = "";
    private String[] scopeValidators = null;
    private boolean pkceSupportPlain;
    private boolean pkceMandatory;
    private String state;
    private long userAccessTokenExpiryTime;
    private long applicationAccessTokenExpiryTime;
    private long refreshTokenExpiryTime;
    private String[] audiences;
    private boolean bypassClientCredentials;
    private String renewRefreshTokenEnabled;
    // OIDC related properties
    private boolean isRequestObjectSignatureValidationEnabled;
    private boolean isIdTokenEncryptionEnabled;
    private String idTokenEncryptionAlgorithm;
    private String idTokenEncryptionMethod;
    private String backChannelLogoutUrl;
    private String frontchannelLogoutUrl;
    private long idTokenExpiryTime;
    private String tokenType;
    private String tokenBindingType;
    private boolean tokenRevocationWithIDPSessionTerminationEnabled;
    private boolean tokenBindingValidationEnabled;
    private String tokenEndpointAuthMethod;
    private String tokenEndpointAuthSignatureAlgorithm;
    private String sectorIdentifierURI;
    private String idTokenSignatureAlgorithm;
    private String requestObjectSignatureAlgorithm;
    private String tlsClientAuthSubjectDN;
    private boolean requirePushedAuthorizationRequests;
    private boolean tlsClientCertificateBoundAccessTokens;
    private String subjectType;
    private String requestObjectEncryptionAlgorithm;
    private String requestObjectEncryptionMethod;
    private String jwksURI;

    public String getJwksURI() {

        return jwksURI;
    }
    public void setJwksURI(String jwksURi) {

        this.jwksURI = jwksURi;
    }
    public long getUserAccessTokenExpiryTime() {
        return userAccessTokenExpiryTime;
    }

    public void setUserAccessTokenExpiryTime(long userAccessTokenExpiryTime) {
        this.userAccessTokenExpiryTime = userAccessTokenExpiryTime;
    }

    public long getApplicationAccessTokenExpiryTime() {
        return applicationAccessTokenExpiryTime;
    }

    public void setApplicationAccessTokenExpiryTime(long applicationAccessTokenExpiryTime) {
        this.applicationAccessTokenExpiryTime = applicationAccessTokenExpiryTime;
    }

    public long getRefreshTokenExpiryTime() {
        return refreshTokenExpiryTime;
    }

    public void setRefreshTokenExpiryTime(long refreshTokenExpiryTime) {
        this.refreshTokenExpiryTime = refreshTokenExpiryTime;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public String getOauthConsumerKey() {
        return oauthConsumerKey;
    }

    public void setOauthConsumerKey(String oauthConsumerKey) {
        this.oauthConsumerKey = oauthConsumerKey;
    }

    public String getOauthConsumerSecret() {
        return oauthConsumerSecret;
    }

    public void setOauthConsumerSecret(String oauthConsumerSecret) {
        this.oauthConsumerSecret = oauthConsumerSecret;
    }

    public String getOAuthVersion() {
        return oauthVersion;
    }

    public void setOAuthVersion(String oAuthVersion) {
        this.oauthVersion = oAuthVersion;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(String grantTypes) {

        if (grantTypes != null) {
            this.grantTypes = grantTypes;
        }
    }

    public String[] getScopeValidators() {
        return scopeValidators;
    }

    public void setScopeValidators(String[] scopeValidators) {
        this.scopeValidators = scopeValidators;
    }

    public boolean getPkceSupportPlain() {
        return pkceSupportPlain;
    }

    public void setPkceSupportPlain(boolean pkceSupportPlain) {
        this.pkceSupportPlain = pkceSupportPlain;
    }

    public boolean getPkceMandatory() {
        return pkceMandatory;
    }

    public void setPkceMandatory(boolean pkceMandatory) {
        this.pkceMandatory = pkceMandatory;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getState() {
        return state;
    }

    public String[] getAudiences() {
        return audiences;
    }

    public void setAudiences(String[] audiences) {

        if (audiences != null) {
            this.audiences = audiences;
        }
    }

    public boolean isRequestObjectSignatureValidationEnabled() {
        return isRequestObjectSignatureValidationEnabled;
    }

    public void setRequestObjectSignatureValidationEnabled(boolean requestObjectSignatureValidationEnabled) {
        this.isRequestObjectSignatureValidationEnabled = requestObjectSignatureValidationEnabled;
    }

    public boolean isIdTokenEncryptionEnabled() {
        return isIdTokenEncryptionEnabled;
    }

    public String getIdTokenEncryptionAlgorithm() {
        return idTokenEncryptionAlgorithm;
    }

    public String getIdTokenEncryptionMethod() {
        return idTokenEncryptionMethod;
    }

    public void setIdTokenEncryptionAlgorithm(String idTokenEncryptionAlgorithm) {
        this.idTokenEncryptionAlgorithm = idTokenEncryptionAlgorithm;
    }

    public void setIdTokenEncryptionMethod(String idTokenEncryptionMethod) {
        this.idTokenEncryptionMethod = idTokenEncryptionMethod;
    }

    public void setIdTokenEncryptionEnabled(boolean idTokenEncryptionEnabled) {
        this.isIdTokenEncryptionEnabled = idTokenEncryptionEnabled;
    }

    public void setBackChannelLogoutUrl(String backChannelLogoutUrl) {
        this.backChannelLogoutUrl = backChannelLogoutUrl;
    }

    public String getBackChannelLogoutUrl() {
        return backChannelLogoutUrl;
    }

    public String getFrontchannelLogoutUrl() {
        return frontchannelLogoutUrl;
    }

    public void setFrontchannelLogoutUrl(String frontchannelLogoutUrl) {
        this.frontchannelLogoutUrl = frontchannelLogoutUrl;
    }

    public long getIdTokenExpiryTime() {

        return idTokenExpiryTime;
    }

    public void setIdTokenExpiryTime(long idTokenExpiryTime) {
        this.idTokenExpiryTime = idTokenExpiryTime;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public boolean isBypassClientCredentials() {
        return bypassClientCredentials;
    }

    /**
     * This method is deprecated. Use the 'isBypassClientCredentials' method instead.
     */
    @Deprecated
    public boolean getBypassClientCredentials() {
        return bypassClientCredentials;
    }

    public void setBypassClientCredentials(boolean isPublicClient) {
        this.bypassClientCredentials = isPublicClient;
    }

    public void setRenewRefreshTokenEnabled(String renewRefreshTokenEnabled) {

        this.renewRefreshTokenEnabled = renewRefreshTokenEnabled;
    }

    public String getRenewRefreshTokenEnabled() {

        return renewRefreshTokenEnabled;
    }

    public String getTokenBindingType() {

        return tokenBindingType;
    }

    public void setTokenBindingType(String tokenBindingType) {

        this.tokenBindingType = tokenBindingType;
    }

    public boolean isTokenRevocationWithIDPSessionTerminationEnabled() {

        return tokenRevocationWithIDPSessionTerminationEnabled;
    }

    public void setTokenRevocationWithIDPSessionTerminationEnabled(
            boolean tokenRevocationWithIDPSessionTerminationEnabled) {

        this.tokenRevocationWithIDPSessionTerminationEnabled = tokenRevocationWithIDPSessionTerminationEnabled;
    }

    public boolean isTokenBindingValidationEnabled() {

        return tokenBindingValidationEnabled;
    }

    public void setTokenBindingValidationEnabled(boolean tokenBindingValidationEnabled) {

        this.tokenBindingValidationEnabled = tokenBindingValidationEnabled;
    }

    public String getTokenEndpointAuthMethod() {

        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {

        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public String getTokenEndpointAuthSignatureAlgorithm() {

        return tokenEndpointAuthSignatureAlgorithm;
    }

    public void setTokenEndpointAuthSignatureAlgorithm(String tokenEndpointAuthSignatureAlgorithm) {

        this.tokenEndpointAuthSignatureAlgorithm = tokenEndpointAuthSignatureAlgorithm;
    }

    public String getSectorIdentifierURI() {

        return sectorIdentifierURI;
    }

    public void setSectorIdentifierURI(String sectorIdentifierURI) {

        this.sectorIdentifierURI = sectorIdentifierURI;
    }
    public String getRequestObjectSignatureAlgorithm() {

        return requestObjectSignatureAlgorithm;
    }

    public void setRequestObjectSignatureAlgorithm(String requestObjectSignatureAlgorithm) {

        this.requestObjectSignatureAlgorithm = requestObjectSignatureAlgorithm;
    }

    public String getTlsClientAuthSubjectDN() {

        return tlsClientAuthSubjectDN;
    }

    public void setTlsClientAuthSubjectDN(String tlsClientAuthSubjectDN) {

        this.tlsClientAuthSubjectDN = tlsClientAuthSubjectDN;
    }

    public boolean getRequirePushedAuthorizationRequests() {

        return requirePushedAuthorizationRequests;
    }

    public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {

        this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
    }

    public boolean getTlsClientCertificateBoundAccessTokens() {

        return tlsClientCertificateBoundAccessTokens;
    }

    public void setTlsClientCertificateBoundAccessTokens(boolean tlsClientCertificateBoundAccessTokens) {

        this.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens;
    }

    public String getSubjectType() {

        return subjectType;
    }

    public void setSubjectType(String subjectType) {

        this.subjectType = subjectType;
    }

    public String getRequestObjectEncryptionAlgorithm() {

        return requestObjectEncryptionAlgorithm;
    }

    public void setRequestObjectEncryptionAlgorithm(String requestObjectEncryptionAlgorithm) {

        this.requestObjectEncryptionAlgorithm = requestObjectEncryptionAlgorithm;
    }

    public String getRequestObjectEncryptionMethod() {

        return requestObjectEncryptionMethod;
    }

    public void setRequestObjectEncryptionMethod(String requestObjectEncryptionMethod) {

        this.requestObjectEncryptionMethod = requestObjectEncryptionMethod;
    }
    public String getIdTokenSignatureAlgorithm() {

        return idTokenSignatureAlgorithm;
    }

    public void setIdTokenSignatureAlgorithm(String idTokenSignatureAlgorithm) {

        this.idTokenSignatureAlgorithm = idTokenSignatureAlgorithm;
    }
}

