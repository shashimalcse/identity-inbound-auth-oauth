/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

/**
 * The AccessTokenProvider interface defines the contract for classes that are responsible
 * for verifying and providing access tokens. Implementing classes should offer methods
 * to retrieve access tokens based on token data objects, with the option to include expired
 * tokens in the verification process and handle potential exceptions.
 */
public interface AccessTokenProvider {

    /**
     * Retrieves and verifies an access token based on the provided access token data object,
     * with an option to include expired tokens in the verification process.
     *
     * @param accessToken    The access token data object to retrieve and verify.
     * @param includeExpired A boolean flag indicating whether to include expired tokens in the verification.
     *                       Set to true to include expired tokens, false to exclude them.
     * @return The AccessTokenDO if the token is valid (ACTIVE or, optionally, EXPIRED), or null if the token
     * is not found either in ACTIVE or EXPIRED states when includeExpired is true. The method should throw
     * IllegalArgumentException if the access token is in an inactive or invalid state (e.g., 'REVOKED' or 'INVALID')
     * when includeExpired is false.
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    AccessTokenDO getVerifiedAccessToken(String accessToken, boolean includeExpired) throws IdentityOAuth2Exception;
}
