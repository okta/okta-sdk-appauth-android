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

import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedList;
import java.util.List;

/**
 * A parser for {@link JSONObject} that provides convenient methods for when JSON is contractual.
 */
public class JsonParser {

    /**
     * Creates a new JsonParser for the given {@link JSONObject}.
     *
     * @param jsonObject The JSON object to parse
     * @return A new JsonParser object
     */
    public static JsonParser forJson(@NonNull final JSONObject jsonObject) {
        return new JsonParser(jsonObject);
    }

    private final JSONObject mJson;

    private JsonParser(@NonNull final JSONObject mJson) {
        this.mJson = mJson;
    }

    /**
     * Gets a String from the JSON object with the given name if it exists. Returns
     * {@code null} if the property is missing or the value is empty or blank.
     *
     * @param propName The name of the JSON property
     * @return The String value of the property with the given name or {@code null} if the property
     *     is missing or if the value is empty or blank
     */
    @Nullable
    public String getOptionalString(String propName) {
        String value = mJson.optString(propName);
        value = value.trim();
        if (TextUtils.isEmpty(value)) {
            return null;
        }

        return value;
    }

    /**
     * Gets a String from the JSON object with the given name.
     *
     * @param propName The name of the JSON property
     * @return The String value of the property with the given name
     * @throws InvalidJsonDocumentException When the property is missing or the value is empty or
     *     blank
     */
    @NonNull
    public String getRequiredString(String propName)
            throws InvalidJsonDocumentException {
        String value = getOptionalString(propName);
        if (TextUtils.isEmpty(value)) {
            throw new InvalidJsonDocumentException(
                    propName + " is required but not specified in the document");
        }

        return value;
    }

    /**
     * Gets a Uri from the JSON object with the given name.
     *
     * @param propName The name of the JSON property
     * @return The Uri value of the property with the given name
     * @throws InvalidJsonDocumentException When the property is missing or the value is empty or
     *     blank
     */
    @NonNull
    public Uri getRequiredUri(String propName)
            throws InvalidJsonDocumentException {
        String uriStr = getRequiredString(propName);
        Uri uri;
        try {
            uri = Uri.parse(uriStr);
        } catch (Throwable ex) {
            throw new InvalidJsonDocumentException(propName + " could not be parsed", ex);
        }

        if (!uri.isHierarchical() || !uri.isAbsolute()) {
            throw new InvalidJsonDocumentException(
                    propName + " must be hierarchical and absolute");
        }

        if (!TextUtils.isEmpty(uri.getEncodedUserInfo())) {
            throw new InvalidJsonDocumentException(propName + " must not have user info");
        }

        if (!TextUtils.isEmpty(uri.getEncodedQuery())) {
            throw new InvalidJsonDocumentException(propName + " must not have query parameters");
        }

        if (!TextUtils.isEmpty(uri.getEncodedFragment())) {
            throw new InvalidJsonDocumentException(propName + " must not have a fragment");
        }

        return uri;
    }

    /**
     * Gets an HTTPS Uri from the JSON object with the given name.
     *
     * @param propName The name of the JSON property
     * @return The Uri value of the property with the given name
     * @throws InvalidJsonDocumentException When the property is missing, the value is empty
     *     or blank, or the scheme of the Uri is not "https"
     */
    @NonNull
    public Uri getRequiredHttpsUri(String propName)
            throws InvalidJsonDocumentException {
        Uri uri = getRequiredUri(propName);
        String scheme = uri.getScheme();
        if (TextUtils.isEmpty(scheme) || !"https".equals(scheme)) {
            throw new InvalidJsonDocumentException(
                    propName + " must have an https scheme, but found: \"" + scheme + "\"");
        }

        return uri;
    }

    /**
     * Gets a List of Strings from the JSON object with the given name.
     * The referenced property must be a {@link JSONArray}. The values of the array will be
     * converted to Strings.
     *
     * @param propName The name of the JSON array property
     * @return The List of String values for the property with the given name
     * @throws InvalidJsonDocumentException When the property is missing or the array is empty
     */
    @NonNull
    public List<String> getRequiredStringArray(String propName)
            throws InvalidJsonDocumentException {
        JSONArray stringsJsonArray = mJson.optJSONArray(propName);
        if (stringsJsonArray == null || stringsJsonArray.length() == 0) {
            throw new InvalidJsonDocumentException(
                    propName + " is required but not specified in the document");
        }

        List<String> scopes = new LinkedList<>();
        for (int i = 0; i < stringsJsonArray.length(); ++i) {
            String value = stringsJsonArray.optString(i);
            if (TextUtils.isEmpty(value)) {
                throw new InvalidJsonDocumentException(
                        propName + " must have an array of Strings");
            }
            scopes.add(value);
        }

        return scopes;
    }
}
