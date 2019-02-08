/*
 * Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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
package com.okta.auth.http;

import android.net.Uri;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RestrictTo;

import com.okta.appauth.android.BuildConfig;
import com.okta.openid.appauth.Preconditions;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static android.support.annotation.RestrictTo.Scope.LIBRARY_GROUP;

@RestrictTo(LIBRARY_GROUP)
public final class HttpRequest {
    private static final String DEFAULT_ENCODING = "UTF-8";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String DEFAULT_CONTENT_TYPE =
            String.format("application/x-www-form-urlencoded; charset=%s", DEFAULT_ENCODING);
    private static final String JSON_CONTENT_TYPE = String.format("application/json; charset=%s", DEFAULT_ENCODING);
    private static final String USER_AGENT = "User-Agent";
    private static final String USER_AGENT_HEADER = "Android/" + Build.VERSION.SDK_INT + " " +
            BuildConfig.APPLICATION_ID + "/" + BuildConfig.VERSION_NAME;

    private static final int HTTP_CONTINUE = 100;

    public enum RequestMethod {
        GET, POST
    }

    private RequestMethod mRequestMethod;
    private Map<String, String> mRequestProperties;
    private Map<String, String> mPostParameters;
    private int mConnectionTimeoutMs;
    private int mReadTimeOutMs;
    private Uri mUri;

    private HttpRequest(Builder builder) {
        mRequestMethod = builder.mRequestMethod;
        mRequestProperties = builder.mRequestProperties;
        mReadTimeOutMs = builder.mReadTimeOutMs;
        mConnectionTimeoutMs = builder.mConnectionTimeoutMs;
        mPostParameters = builder.mPostParameters;
        mUri = builder.mUri;
    }

    public HttpResponse executeRequest() throws IOException {
        HttpURLConnection connection = openConnection();
        boolean keepOpen = false;
        try {
            int responseCode = connection.getResponseCode();
            if (responseCode == -1) {
                throw new IOException("Invalid response code -1 no code can be discerned");
            }
            if (!hasResponseBody(responseCode)) {
                return new HttpResponse(responseCode, connection.getHeaderFields());
            }
            keepOpen = true;
            return new HttpResponse(
                    responseCode, connection.getHeaderFields(),
                    connection.getContentLength(), connection);
        } finally {
            if (!keepOpen) {
                connection.disconnect();
            }
        }
    }

    @NonNull
    private HttpURLConnection openConnection() throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(mUri.toString()).openConnection();
        conn.setConnectTimeout(mConnectionTimeoutMs);
        conn.setReadTimeout(mReadTimeOutMs);
        conn.setInstanceFollowRedirects(false);
        if (mRequestProperties == null || !mRequestProperties.containsKey(USER_AGENT)) {
            conn.setRequestProperty(USER_AGENT, USER_AGENT_HEADER);
        }
        if (mRequestProperties == null || !mRequestProperties.containsKey(CONTENT_TYPE)) {
            conn.setRequestProperty(CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
        }
        if (mRequestProperties != null) {
            for (String property : mRequestProperties.keySet()) {
                conn.setRequestProperty(property, mRequestProperties.get(property));
            }
        }

        if (mRequestMethod == RequestMethod.GET) {
            conn.setRequestMethod("GET");
            conn.setDoInput(true);
        } else if (mRequestMethod == RequestMethod.POST) {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            if (mPostParameters != null && !mPostParameters.isEmpty()) {
                DataOutputStream out = new DataOutputStream(conn.getOutputStream());
                out.write(encodePostParameters());
                out.close();
            }
        }
        return conn;
    }

    private byte[] encodePostParameters() {
        StringBuilder encodedParams = new StringBuilder();
        try {
            for (Map.Entry<String, String> entry : mPostParameters.entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "mPostParameters returned a map "
                                            + "containing a null key or value: (%s, %s).",
                                    entry.getKey(), entry.getValue()));
                }
                encodedParams.append(URLEncoder.encode(entry.getKey(), DEFAULT_ENCODING));
                encodedParams.append('=');
                encodedParams.append(URLEncoder.encode(entry.getValue(), DEFAULT_ENCODING));
                encodedParams.append('&');
            }
            return encodedParams.toString().getBytes(DEFAULT_ENCODING);
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("Encoding not supported: " + DEFAULT_ENCODING, uee);
        }
    }

    private boolean hasResponseBody(int responseCode) {
        return !(HTTP_CONTINUE <= responseCode && responseCode < HttpURLConnection.HTTP_OK)
                && responseCode != HttpURLConnection.HTTP_NO_CONTENT
                && responseCode != HttpURLConnection.HTTP_NOT_MODIFIED;
    }

    public static final class Builder {
        private static final String HTTPS_SCHEME = "https";

        private RequestMethod mRequestMethod;
        private Map<String, String> mRequestProperties;
        private Map<String, String> mPostParameters;
        private int mConnectionTimeoutMs = (int) TimeUnit.SECONDS.toMillis(15);
        private int mReadTimeOutMs = (int) TimeUnit.SECONDS.toMillis(10);
        private Uri mUri;

        public Builder() {
        }

        public HttpRequest create() {
            Preconditions.checkNotNull(mUri);
            Preconditions.checkNotNull(mRequestMethod);
            Preconditions.checkArgument(HTTPS_SCHEME.equals(mUri.getScheme()),
                    "only https connections are permitted");
            return new HttpRequest(this);
        }

        public Builder setUri(@NonNull Uri uri) {
            mUri = uri;
            return this;
        }

        public Builder setRequestMethod(@NonNull RequestMethod method) {
            mRequestMethod = method;
            return this;
        }

        public Builder setRequestProperty(@NonNull String key, @NonNull String value) {
            if (mRequestProperties == null) {
                mRequestProperties = new HashMap<>();
            }
            mRequestProperties.put(key, value);
            return this;
        }

        public Builder setRequestProperties(@NonNull Map<String, String> map) {
            if (mRequestProperties == null) {
                mRequestProperties = new HashMap<>();
            }
            mRequestProperties.putAll(map);
            return this;
        }

        public Builder setConnectionTimeoutMs(int timeOut) {
            mConnectionTimeoutMs = timeOut;
            return this;
        }

        public Builder setReadTimeOutMs(int readTimeOut) {
            mReadTimeOutMs = readTimeOut;
            return this;
        }

        public Builder setPostParameter(@NonNull String key, @NonNull String value) {
            if (mPostParameters == null) {
                mPostParameters = new HashMap<>();
            }
            mPostParameters.put(key, value);
            return this;
        }

        public Builder setPostParameters(@NonNull Map<String, String> map) {
            if (mPostParameters == null) {
                mPostParameters = new HashMap<>();
            }
            mPostParameters.putAll(map);
            return this;
        }
    }
}
