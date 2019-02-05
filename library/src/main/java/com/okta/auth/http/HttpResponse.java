package com.okta.auth.http;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class HttpResponse {
    private final int mStatusCode;
    private final Map<String, List<String>> mHeaders;
    private final int mLength;
    private final HttpURLConnection mConnection;

    /**
     * HttpResponse for an empty response body.
     *
     * @param statusCode HTTP status code
     * @param headers    response headers
     */
    public HttpResponse(int statusCode, Map<String, List<String>> headers) {
        this(statusCode, headers, -1, null);
    }

    /**
     * Constructor for HttpResponse.
     *
     * @param statusCode HTTP status code of the response
     * @param headers    response headers
     * @param length     the length of the response.
     * @param connection an {@link HttpURLConnection} httpUrlconnection.
     */
    public HttpResponse(
            int statusCode, Map<String, List<String>> headers, int length, HttpURLConnection connection) {
        mStatusCode = statusCode;
        mHeaders = headers;
        mLength = length;
        mConnection = connection;
    }

    public final int getStatusCode() {
        return mStatusCode;
    }

    public final Map<String, List<String>> getHeaders() {
        return Collections.unmodifiableMap(mHeaders);
    }

    public final int getContentLength() {
        return mLength;
    }

    public final InputStream getContent() {
        InputStream inputStream;
        try {
            inputStream = mConnection.getInputStream();
        } catch (IOException e) {
            inputStream = mConnection.getErrorStream();
        }
        return inputStream;
    }

    public void disconnect() {
        if (mConnection != null) {
            mConnection.disconnect();
        }
    }

    public JSONObject asJson() throws IOException, JSONException {
        JSONObject json;
        if (mStatusCode < HttpURLConnection.HTTP_OK || mStatusCode >= HttpURLConnection.HTTP_MULT_CHOICE) {
            throw new IOException("Invalid status code " + mStatusCode);
        }
        InputStream is = getContent();
        if (is == null) {
            throw new IOException("Input stream must not be null");
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        Writer writer = new StringWriter();
        String line = reader.readLine();
        while (line != null) {
            writer.write(line);
            line = reader.readLine();
        }
        json = new JSONObject(writer.toString());
        return json;
    }
}
