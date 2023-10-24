/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.api.auth.model;

/**
 * Class containing flow status enums.
 */
public enum FlowStatusEnum {

    INCOMPLETE("INCOMPLETE"),
    FAIL_INCOMPLETE("FAIL_INCOMPLETE"),
    SUCCESS_COMPLETED("SUCCESS_COMPLETED"),
    FAIL_COMPLETED("FAIL_COMPLETED");

    private String value;

    FlowStatusEnum(String v) {

        value = v;
    }

    public String value() {

        return value;
    }

    @Override
    public String toString() {

        return String.valueOf(value);
    }

    /**
     * This method is used to get the FlowStatusEnum from the given value.
     *
     * @param value The value of the FlowStatusEnum.
     * @return The FlowStatusEnum.
     */
    public static FlowStatusEnum fromValue(String value) {

        for (FlowStatusEnum flowStatus : FlowStatusEnum.values()) {
            if (flowStatus.value.equals(value)) {
                return flowStatus;
            }
        }
        return null;
    }
}

