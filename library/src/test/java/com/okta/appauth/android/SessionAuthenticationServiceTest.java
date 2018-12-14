package com.okta.appauth.android;

import android.net.Uri;

import com.okta.ConnectionBuilderForTest;
import com.okta.TestUtils;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.ResponseTypeValues;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;

import java.io.IOException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
public class SessionAuthenticationServiceTest {
    AuthStateManager mAuthStateManager;
    AuthorizationService mAuthService;

    private SessionAuthenticationService sessionAuthenticationService;
    private AuthorizationRequest.Builder authorizationRequest;
    private AuthorizationRequest request;
    private CustomDispatcher dispatcher;

    private static final String VALID_SESSION = "valid_session_token";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        mAuthStateManager = AuthStateManager.getInstance(RuntimeEnvironment.application);

        MockWebServer server = new MockWebServer();
        dispatcher = new CustomDispatcher();
        server.setDispatcher(dispatcher);

        SSLSocketFactory sslSocketFactory = TestUtils.getSSL(this);
        HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
        server.useHttps(sslSocketFactory, false);
        server.start();
        String baseUrl = server.url("/").toString();
        authorizationRequest = TestUtils.getMinimalAuthRequestBuilder(baseUrl, ResponseTypeValues.CODE);

        mAuthService = new AuthorizationService(RuntimeEnvironment.application.getApplicationContext(), new AppAuthConfiguration.Builder().setConnectionBuilder(ConnectionBuilderForTest.INSTANCE).build());

        sessionAuthenticationService = new SessionAuthenticationService(mAuthStateManager, mAuthService);

        request = authorizationRequest.build();
        dispatcher.nonce = request.nonce;
    }

    // Removed this test method until AppAuth will be merged in this project with another package
    public void testValidCredentialsPerformAuthorizationRequest() throws IOException {
        FakeNativeOktaAuthListener listener = new FakeNativeOktaAuthListener();

        sessionAuthenticationService.performAuthorizationRequest(request, VALID_SESSION, listener);

        assertTrue(listener.hasCalledOnSuccess());
    }

    @Test
    public void testInValidCredentialsPerformAuthorizationRequest() {
        FakeNativeOktaAuthListener listener = new FakeNativeOktaAuthListener();

        sessionAuthenticationService.performAuthorizationRequest(request, null, listener);

        assertTrue(listener.hasCalledOnTokenFailure());
    }

    @Test
    public void testNullListenerPerformAuthorizationRequest() {
        sessionAuthenticationService.performAuthorizationRequest(request, VALID_SESSION, null);
        sessionAuthenticationService.performAuthorizationRequest(request, null, null);
    }

    static class CustomDispatcher extends Dispatcher {
        String nonce;

        @Override
        public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            if (request.getPath().contains(TestUtils.TEST_AUTHORIZATION_ENDPOINT)){
                return new MockResponse().setResponseCode(302).addHeader("Location",TestUtils.TEST_APP_REDIRECT_URI+"?code=valid_code&state=random_state").setBody("Test");
            } else if (request.getPath().contains(TestUtils.TEST_TOKEN_ENDPOINT)){
                String baseUrl = TestUtils.getBaseUrl(Uri.parse(request.getRequestUrl().toString()));
                return  new MockResponse().setResponseCode(200).setBody(TestUtils.getValidTokenResponse(baseUrl, nonce));
            }
            return new MockResponse().setResponseCode(404);
        }
    }


}