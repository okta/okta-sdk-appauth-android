package com.okta.appauth.android;

import android.app.PendingIntent;
import android.content.Context;

import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.customtabs.CustomTabsIntent;
import com.okta.ReflectionUtils;
import com.okta.TestUtils;

import net.openid.appauth.*;
import net.openid.appauth.connectivity.DefaultConnectionBuilder;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;

import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class OktaAppAuthTest {
    private static final String TAG = "OktaAppAuth";

    @Mock
    AuthorizationService mAuthService;
    @Mock
    AuthStateManager mAuthStateManager;
    @Mock
    OAuthClientConfiguration mConfiguration;
    @Mock
    AuthState mAuthState;
    @Mock
    ClientAuthentication mClientAuthentication;
    private OktaAppAuth sut;
    private Context mContext;

    @Before
    public void setUp() throws Exception {
        mContext = RuntimeEnvironment.application.getApplicationContext();
        MockitoAnnotations.initMocks(this);
        sut = OktaAppAuth.getInstance(RuntimeEnvironment.application.getApplicationContext());
        sut.mAuthService.set(mAuthService);
        ReflectionUtils.refectSetValue(sut, "mAuthStateManager", mAuthStateManager);
        ReflectionUtils.refectSetValue(sut, "mConfiguration", mConfiguration);
        sut.mExecutor = TestUtils.buildSyncynchronesExecutorService();
        when(mAuthStateManager.getCurrent()).thenReturn(mAuthState);
    }

    @Test
    public void testDisposeNullsAuthenticationService() {
        sut = OktaAppAuth.getInstance(mContext);
        sut.mAuthService.set(new AuthorizationService(mContext));
        assertThat(sut.mAuthService.get()).isNotNull();
        sut.dispose();
        assertThat(sut.mAuthService.get()).isNull();
    }

    @Test
    public void testAuthServiceCreatesWhenNeeded() {
        sut = OktaAppAuth.getInstance(mContext);
        sut.mAuthService.set(null);
        sut.createAuthorizationServiceIfNeeded();
        assertThat(sut.mAuthService).isNotNull();
    }

    @Test
    public void testAuthServiceUsesOriginalWhenSet() {
        AuthorizationService authorizationService = new AuthorizationService(mContext);
        sut = OktaAppAuth.getInstance(mContext);
        sut.mAuthService.set(authorizationService);
        sut.createAuthorizationServiceIfNeeded();
        assertThat(sut.mAuthService.get()).isNotNull();
        assertThat(sut.mAuthService.get()).isSameAs(authorizationService);
    }

    @Test
    public void testAuthServiceRecreatesWhenDisposed() {
        AuthorizationService authorizationService = new AuthorizationService(mContext);
        sut.mAuthService.set(authorizationService);
        sut.dispose();
        sut.createAuthorizationServiceIfNeeded();
        assertThat(sut.mAuthService.get()).isNotNull();
        assertThat(sut.mAuthService.get()).isNotSameAs(authorizationService);
    }

    @Test
    public void testRefreshWithoutTokenCallsListener() {
        FakeOktaAuthListener listener = new FakeOktaAuthListener();
        sut.refreshAccessToken(listener);
        assertThat(listener.hasCalledOnTokenFailure()).isTrue();
        assertThat(listener.getTokenExceptions().get(0))
                .isEqualTo(AuthorizationException.TokenRequestErrors.INVALID_REQUEST);
    }

    @Test
    public void testRefreshFailsClientAuthenticationCallsListener()
            throws ClientAuthentication.UnsupportedAuthenticationMethod {

        when(mAuthState.getRefreshToken()).thenReturn("refreshTokenHere");
        when(mAuthState.getClientAuthentication())
                .thenThrow(new ClientAuthentication.
                        UnsupportedAuthenticationMethod("tokenEndpointAuthMethod"));
        FakeOktaAuthListener listener = new FakeOktaAuthListener();

        sut.refreshAccessToken(listener);

        verify(mAuthState, times(1)).getClientAuthentication();
        assertThat(listener.hasCalledOnTokenFailure()).isTrue();
        assertThat(listener.getTokenExceptions().get(0))
                .isEqualTo(AuthorizationException.TokenRequestErrors.INVALID_REQUEST);
    }

    @Test
    public void testSignOutFromOkta() {
        PendingIntent success = mock(PendingIntent.class);
        PendingIntent failure = mock(PendingIntent.class);
        AuthState authState = mock(AuthState.class);
        String idToken = TestUtils.getUnsignedIdToken();

        when(mAuthService.createCustomTabsIntentBuilder(any(Uri.class)))
                .thenReturn(new CustomTabsIntent.Builder());
        when(mAuthStateManager.getCurrent()).thenReturn(authState);
        when(authState.getAuthorizationServiceConfiguration())
                .thenReturn(TestUtils.getTestServiceConfig());
        when(authState.isAuthorized()).thenReturn(true);
        when(authState.getIdToken()).thenReturn(idToken);
        when(mConfiguration.getEndSessionRedirectUri())
                .thenReturn(TestUtils.TEST_APP_REDIRECT_URI);
        when(mConfiguration.hasConfigurationChanged()).thenReturn(false);

        ArgumentCaptor<EndSessionRequest> argument = ArgumentCaptor.forClass(EndSessionRequest.class);

        sut.signOutFromOkta(mContext, success, failure);

        verify(mAuthService, times(1))
                .performEndOfSessionRequest(
                        argument.capture()
                        ,any(PendingIntent.class)
                        ,any(PendingIntent.class)
                        ,any(CustomTabsIntent.class)
                );

        assertThat(argument.getValue().idToken)
                .isEqualTo(idToken);
        assertThat(argument.getValue().configuration.toJsonString())
                .isEqualTo(TestUtils.getTestServiceConfig().toJsonString());
        assertThat(argument.getValue().redirectUri)
                .isEqualTo(TestUtils.TEST_APP_REDIRECT_URI);
    }

    @Test(expected = IllegalStateException.class)
    public void testLogoutNoLogedinUserFoundException(){
        PendingIntent success = mock(PendingIntent.class);
        PendingIntent failure = mock(PendingIntent.class);
        AuthState authState = mock(AuthState.class);

        when(mAuthStateManager.getCurrent()).thenReturn(authState);
        when(authState.isAuthorized()).thenReturn(false);
        when(mConfiguration.hasConfigurationChanged()).thenReturn(false);
        when(authState.getAuthorizationServiceConfiguration())
                .thenReturn(TestUtils.getTestServiceConfig());

        sut.signOutFromOkta(mContext, success, failure);
    }

    @Test
    public void testLoginWithoutPayloadSuccess() {
        PendingIntent success = mock(PendingIntent.class);
        PendingIntent failure = mock(PendingIntent.class);
        AuthState authState = mock(AuthState.class);
        AuthorizationRequest expectedRequest = TestUtils.getTestAuthRequest();

        when(mAuthService.createCustomTabsIntentBuilder(any(Uri.class)))
                .thenReturn(new CustomTabsIntent.Builder());
        when(mAuthStateManager.getCurrent()).thenReturn(authState);
        when(authState.getAuthorizationServiceConfiguration())
                .thenReturn(TestUtils.getTestServiceConfig());
        sut.mAuthRequest.set(TestUtils.getTestAuthRequest());

        sut.login(mContext, success, failure);

        ArgumentCaptor<AuthorizationRequest> argument = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(mAuthService, times(1))
                .performAuthorizationRequest(
                        argument.capture()
                        ,any(PendingIntent.class)
                        ,any(PendingIntent.class)
                        ,any(CustomTabsIntent.class)
                );

        assertThat(expectedRequest.clientId)
                .isEqualTo(argument.getValue().clientId);
        assertThat(expectedRequest.configuration.toJsonString())
                .isEqualTo(argument.getValue().configuration.toJsonString());
    }

    @Test
    public void testLoginWithPayloadSuccess() {
        PendingIntent success = mock(PendingIntent.class);
        PendingIntent failure = mock(PendingIntent.class);
        AuthState authState = mock(AuthState.class);

        when(mAuthService.createCustomTabsIntentBuilder(any(Uri.class)))
                .thenReturn(new CustomTabsIntent.Builder());
        when(mAuthStateManager.getCurrent()).thenReturn(authState);
        when(authState.getAuthorizationServiceConfiguration())
                .thenReturn(TestUtils.getTestServiceConfig());
        when(mConfiguration.getRedirectUri()).thenReturn(TestUtils.TEST_APP_REDIRECT_URI);
        when(mConfiguration.getScopes()).thenReturn(new HashSet<>(TestUtils.TEST_SCOPES_SUPPORTED));
        sut.mClientId.set(TestUtils.TEST_CLIENT_ID);

        AuthenticationPayload payload = new AuthenticationPayload.Builder()
                .addParameter("testName", "testValue")
                .setState("testState")
                .setLoginHint("loginHint")
                .build();

        sut.login(mContext, success, failure, payload);

        ArgumentCaptor<AuthorizationRequest> argument = ArgumentCaptor
                .forClass(AuthorizationRequest.class);

        verify(mAuthService, times(1))
                .performAuthorizationRequest(
                        argument.capture()
                        ,any(PendingIntent.class)
                        ,any(PendingIntent.class)
                        ,any(CustomTabsIntent.class)
                );

        assertThat(argument.getValue().loginHint)
                .isEqualTo(payload.getLoginHint());
        assertThat(argument.getValue().additionalParameters)
                .isEqualTo(payload.getAdditionalParameters());
        assertThat(argument.getValue().state)
                .isEqualTo(payload.getState());
    }

    @Test
    public void testLoginIllegalStateExceptionConfigurationChanged(){
        PendingIntent success = mock(PendingIntent.class);
        PendingIntent failure = mock(PendingIntent.class);
        when(mConfiguration.hasConfigurationChanged()).thenReturn(true);

        try {
            sut.login(mContext, success, failure);
        } catch (IllegalStateException ex) {
            assertThat(ex).isInstanceOf(IllegalStateException.class);
            assertThat(ex.getMessage()).contains("Okta Configuration has changed");
            return;
        }
        fail("Expected exception not thrown");
    }

    @Test
    public void testLoginIllegalStateExceptionNoAuthorizationConfiguration(){
        PendingIntent success = mock(PendingIntent.class);
        PendingIntent failure = mock(PendingIntent.class);
        AuthState mockedState = mock(AuthState.class);
        when(mAuthStateManager.getCurrent()).thenReturn(mockedState);
        when(mockedState.getAuthorizationServiceConfiguration()).thenReturn(null);

        try {
            sut.login(mContext, success, failure);
        } catch (IllegalStateException ex) {
            assertThat(ex).isInstanceOf(IllegalStateException.class);
            assertThat(ex.getMessage()).contains("Okta should be initialized first");
            return;
        }
        fail("Expected exception not thrown");
    }

    @Test
    public void testRefreshCallsIntoAppAuth() throws ClientAuthentication.UnsupportedAuthenticationMethod {
        TokenRequest tokenRequest = mock(TokenRequest.class);
        FakeOktaAuthListener listener = new FakeOktaAuthListener();
        when(mAuthState.getRefreshToken()).thenReturn("refreshTokenHere");
        when(mAuthState.getClientAuthentication()).thenReturn(mClientAuthentication);
        when(mAuthState.createTokenRefreshRequest()).thenReturn(tokenRequest);
        sut.refreshAccessToken(listener);
        verify(mAuthService, times(1))
                .performTokenRequest(
                        any(TokenRequest.class),
                        any(ClientAuthentication.class),
                        any(AuthorizationService.TokenResponseCallback.class));
    }

    @Test
    public void testGetTokenSuccess() {
        String testIdToken = "testIdToken";
        String testAccessToken = "testAccessToken";
        String testRefreshToken = "testRefreshToken";
        when(mAuthStateManager.getCurrent()).thenReturn(mAuthState);
        when(mAuthState.getIdToken()).thenReturn(testIdToken);
        when(mAuthState.getRefreshToken()).thenReturn(testRefreshToken);
        when(mAuthState.getAccessToken()).thenReturn(testAccessToken);
        Tokens tokens = sut.getTokens();

        assertThat(tokens.getAccessToken()).isEqualTo(testAccessToken);
        assertThat(tokens.getIdToken()).isEqualTo(testIdToken);
        assertThat(tokens.getRefreshToken()).isEqualTo(testRefreshToken);
    }

    @Test
    public void testAccessTokenRevocationSuccess() throws JSONException, InterruptedException {
        final String testAccessToken = "testAccesToken";
        final String  testClientId = "clientId";
        AuthorizationServiceDiscovery discoveryMoc = mock(AuthorizationServiceDiscovery.class);
        AuthorizationServiceConfiguration configurationMoc = mock(AuthorizationServiceConfiguration.class);

        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                String url = request.getPath();
                if (url.contains(TestUtils.REVOKE_URI)
                       && url.contains(testAccessToken)
                        && url.contains(testClientId)){
                    return new MockResponse().setResponseCode(200);
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        String tokenRevocationUrl = mockWebServer.url(TestUtils.REVOKE_URI).toString();
        sut.mClientId.set(testClientId);

        ReflectionUtils.refectSetValue(discoveryMoc, "docJson", TestUtils
                .addField(new JSONObject(),
                        RevokeTokenRequest.REVOKE_ENDPOINT_KEY, tokenRevocationUrl
                ));

        ReflectionUtils.refectSetValue(configurationMoc, "discoveryDoc", discoveryMoc);

        when(mAuthStateManager.getCurrent()).thenReturn(mAuthState);
        when(mAuthState.getAuthorizationServiceConfiguration())
                .thenReturn(configurationMoc);

        final AtomicBoolean isPassed = new AtomicBoolean();
        final CountDownLatch latch = new CountDownLatch(1);

        sut.revoke(testAccessToken, new OktaAppAuth.OktaRevokeListener() {
            @Override
            public void onSuccess() {
                isPassed.set(true);
                latch.countDown();
            }

            @Override
            public void onError(AuthorizationException ex) {
                isPassed.set(false);
                latch.countDown();
            }
        });

        latch.await();
        assertTrue("onError has been called",isPassed.get());
    }

    @Test
    public void testAccessTokenRevocationFailure() throws JSONException, InterruptedException {
        final String testAccessToken = "testAccesToken";
        final String  testClientId = "clientId";
        AuthorizationServiceDiscovery discoveryMoc = mock(AuthorizationServiceDiscovery.class);
        AuthorizationServiceConfiguration configurationMoc = mock(AuthorizationServiceConfiguration.class);

        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                String url = request.getPath();
                if (url.contains(TestUtils.REVOKE_URI)
                        && url.contains(testAccessToken)
                        && url.contains(testClientId)){
                    return new MockResponse().setResponseCode(400);
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        String tokenRevocationUrl = mockWebServer.url(TestUtils.REVOKE_URI).toString();
        sut.mClientId.set(testClientId);

        ReflectionUtils.refectSetValue(discoveryMoc, "docJson", TestUtils
                .addField(new JSONObject(),
                        RevokeTokenRequest.REVOKE_ENDPOINT_KEY, tokenRevocationUrl
                ));

        ReflectionUtils.refectSetValue(configurationMoc, "discoveryDoc", discoveryMoc);

        when(mAuthStateManager.getCurrent()).thenReturn(mAuthState);
        when(mAuthState.getAuthorizationServiceConfiguration())
                .thenReturn(configurationMoc);

        final AtomicBoolean isPassed = new AtomicBoolean();
        final CountDownLatch latch = new CountDownLatch(1);

        sut.revoke(testAccessToken, new OktaAppAuth.OktaRevokeListener() {
            @Override
            public void onSuccess() {
                isPassed.set(false);
                latch.countDown();
            }

            @Override
            public void onError(AuthorizationException ex) {
                if (ex.type == AuthorizationException.TYPE_OAUTH_TOKEN_ERROR) {
                    isPassed.set(true);
                }
                latch.countDown();
            }
        });

        latch.await();
        assertTrue("onSuccess has been called",isPassed.get());
    }

    @Test
    public void testAllTokenRevocationSuccess() throws JSONException, InterruptedException {
        final String testAccessToken = "testAccesToken";
        final String testRefreshToke = "testRefreshToke";
        final String  testClientId = "clientId";
        AuthorizationServiceDiscovery discoveryMoc = mock(AuthorizationServiceDiscovery.class);
        AuthorizationServiceConfiguration configurationMoc = mock(AuthorizationServiceConfiguration.class);

        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                String url = request.getPath();
                if (url.contains(TestUtils.REVOKE_URI)
                        && url.contains(testClientId)
                        && (url.contains(testAccessToken) || url.contains(testRefreshToke))
                        ){
                    return new MockResponse().setResponseCode(200);
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        String tokenRevocationUrl = mockWebServer.url(TestUtils.REVOKE_URI).toString();
        sut.mClientId.set(testClientId);

        ReflectionUtils.refectSetValue(discoveryMoc, "docJson", TestUtils
                .addField(new JSONObject(),
                        RevokeTokenRequest.REVOKE_ENDPOINT_KEY, tokenRevocationUrl
                ));

        ReflectionUtils.refectSetValue(configurationMoc, "discoveryDoc", discoveryMoc);

        when(mAuthStateManager.getCurrent()).thenReturn(mAuthState);
        when(mAuthState.getAuthorizationServiceConfiguration())
                .thenReturn(configurationMoc);
        when(mAuthState.getAccessToken()).thenReturn(testAccessToken);
        when(mAuthState.getRefreshToken()).thenReturn(testRefreshToke);

        when(mAuthState.isAuthorized()).thenReturn(true);

        final AtomicBoolean isPassed = new AtomicBoolean();
        final CountDownLatch latch = new CountDownLatch(1);

        sut.revoke(new OktaAppAuth.OktaRevokeListener() {
            @Override
            public void onSuccess() {
                isPassed.set(true);
                latch.countDown();
            }

            @Override
            public void onError(AuthorizationException ex) {
                isPassed.set(false);
                latch.countDown();
            }
        });

        latch.await();
        assertTrue("onError has been called",isPassed.get());
    }

    @Test
    public void testAllTokenRevocationNoRefreshTokenSuccess() throws JSONException, InterruptedException {
        final String testAccessToken = "testAccesToken";
        final String  testClientId = "clientId";
        AuthorizationServiceDiscovery discoveryMoc = mock(AuthorizationServiceDiscovery.class);
        AuthorizationServiceConfiguration configurationMoc = mock(AuthorizationServiceConfiguration.class);

        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                String url = request.getPath();
                if (url.contains(TestUtils.REVOKE_URI)
                        && url.contains(testClientId)
                        && (url.contains(testAccessToken))
                        ){
                    return new MockResponse().setResponseCode(200);
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        String tokenRevocationUrl = mockWebServer.url(TestUtils.REVOKE_URI).toString();
        sut.mClientId.set(testClientId);

        ReflectionUtils.refectSetValue(discoveryMoc, "docJson", TestUtils
                .addField(new JSONObject(),
                        RevokeTokenRequest.REVOKE_ENDPOINT_KEY, tokenRevocationUrl
                ));

        ReflectionUtils.refectSetValue(configurationMoc, "discoveryDoc", discoveryMoc);

        when(mAuthStateManager.getCurrent()).thenReturn(mAuthState);
        when(mAuthState.getAuthorizationServiceConfiguration())
                .thenReturn(configurationMoc);
        when(mAuthState.getAccessToken()).thenReturn(testAccessToken);
        when(mAuthState.getRefreshToken()).thenReturn(null);

        when(mAuthState.isAuthorized()).thenReturn(true);

        final AtomicBoolean isPassed = new AtomicBoolean();
        final CountDownLatch latch = new CountDownLatch(1);

        sut.revoke(new OktaAppAuth.OktaRevokeListener() {
            @Override
            public void onSuccess() {
                isPassed.set(true);
                latch.countDown();
            }

            @Override
            public void onError(AuthorizationException ex) {
                isPassed.set(false);
                latch.countDown();
            }
        });

        latch.await();
        assertTrue("onError has been called",isPassed.get());
    }

    @Test
    public void testAllTokenRevocationRefreshTokenFailure() throws JSONException, InterruptedException {
        final String testRefreshToken = "testRefreshToken";
        final String  testClientId = "clientId";
        AuthorizationServiceDiscovery discoveryMoc = mock(AuthorizationServiceDiscovery.class);
        AuthorizationServiceConfiguration configurationMoc = mock(AuthorizationServiceConfiguration.class);

        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                String url = request.getPath();
                if (url.contains(TestUtils.REVOKE_URI)
                        && url.contains(testClientId)
                        && (url.contains(testRefreshToken))
                        ){
                    return new MockResponse().setResponseCode(400);
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        String tokenRevocationUrl = mockWebServer.url(TestUtils.REVOKE_URI).toString();
        sut.mClientId.set(testClientId);

        ReflectionUtils.refectSetValue(discoveryMoc, "docJson", TestUtils
                .addField(new JSONObject(),
                        RevokeTokenRequest.REVOKE_ENDPOINT_KEY, tokenRevocationUrl
                ));

        ReflectionUtils.refectSetValue(configurationMoc, "discoveryDoc", discoveryMoc);

        when(mAuthStateManager.getCurrent()).thenReturn(mAuthState);
        when(mAuthState.getAuthorizationServiceConfiguration())
                .thenReturn(configurationMoc);
        when(mAuthState.getRefreshToken()).thenReturn(testRefreshToken);

        when(mAuthState.isAuthorized()).thenReturn(true);

        final AtomicBoolean isPassed = new AtomicBoolean();
        final CountDownLatch latch = new CountDownLatch(1);

        sut.revoke(new OktaAppAuth.OktaRevokeListener() {
            @Override
            public void onSuccess() {
                isPassed.set(false);
                latch.countDown();
            }

            @Override
            public void onError(AuthorizationException ex) {
                if (ex.type == AuthorizationException.TYPE_OAUTH_TOKEN_ERROR) {
                    isPassed.set(true);
                }
                latch.countDown();
            }
        });

        latch.await();
        assertTrue("onSuccess has been called",isPassed.get());
    }

    @Test
    public void testTokenRevocationConfigChangedException() {
        String testToken = "testToken";
        when(mConfiguration.hasConfigurationChanged()).thenReturn(true);
        try {
            sut.revoke(testToken, new OktaAppAuth.OktaRevokeListener() {
                @Override
                public void onSuccess() {
                    fail("Test should fail with exception");
                }

                @Override
                public void onError(AuthorizationException ex) {
                    fail("Test should fail with exception");
                }
            });
        } catch (IllegalStateException ex) {
            assertThat(ex).isInstanceOf(IllegalStateException.class);
            assertThat(ex.getMessage()).contains("Okta Configuration has changed");
            return;
        }
        fail("Test should fail with exception");
    }

    @Test
    public void testTokenRevocationOktaNotInitializedException() {
        String testToken = "testToken";
        AuthState mockedState = mock(AuthState.class);
        when(mAuthStateManager.getCurrent()).thenReturn(mockedState);
        when(mockedState.getAuthorizationServiceConfiguration()).thenReturn(null);
        try {
            sut.revoke(testToken, new OktaAppAuth.OktaRevokeListener() {
                @Override
                public void onSuccess() {
                    fail("Test should fail with exception");
                }

                @Override
                public void onError(AuthorizationException ex) {
                    fail("Test should fail with exception");
                }
            });
        } catch (IllegalStateException ex) {
            assertThat(ex).isInstanceOf(IllegalStateException.class);
            assertThat(ex.getMessage()).contains("Okta should be initialized first");
            return;
        }
        fail("Test should fail with exception");
    }
}