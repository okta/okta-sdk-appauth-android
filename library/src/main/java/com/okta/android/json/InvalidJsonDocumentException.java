/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License,
 * Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the
 * License.
 */

package com.okta.android.json;

/**
 * Thrown to indicate that the {@link org.json.JSONObject} does not meet
 * the expectations of the caller.
 */
public class InvalidJsonDocumentException extends Exception {

    /**
     * Constructs a DataFormatException with the specified detail message.
     *
     * @param reason The String containing the detail message
     */
    public InvalidJsonDocumentException(String reason) {
        super(reason);
    }

    /**
     * Constructs an instance with the given detail message and cause.
     *
     * @param reason The String containing the detail message
     * @param cause The Throwable that is the root cause of the exception
     */
    public InvalidJsonDocumentException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
