# Okta

[![Build Status](https://travis-ci.org/okta/okta-sdk-appauth-android.svg?branch=master)](https://travis-ci.org/okta/okta-sdk-appauth-android)

## Example

To run the example project, clone the repo and run `./gradlew assemble` from the root directory.

```bash
git clone --recurse-submodules https://github.com/okta/okta-sdk-appauth-android.git
cd okta-sdk-appauth-android
./gradlew assemble
```

You can then install the example APK onto an Android device or emulator.

## Installation

Add the `OktaAppAuth` dependency to your `build.gradle` file:

```bash
api 'com.okta.android:appauth-android:0.2.1'
```

## Overview

This library currently supports:

- [OAuth 2.0 Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-4.1) using the [PKCE extension](https://tools.ietf.org/html/rfc7636)

## Getting Started

You can create an Okta developer account at [https://developer.okta.com/](https://developer.okta.com/).

1. After login, from the Admin dashboard, navigate to **Applications**&rarr;**Add Application**
2. Choose **Native** as the platform
3. Populate your new Native OpenID Connect application with values similar to:

| Setting              | Value                                               |
| -------------------- | --------------------------------------------------- |
| Application Name     | Native OpenId Connect App *(must be unique)*        |
| Login URI            | com.okta.example:/callback                          |
| End Session URI      | com.okta.example:/logoutCallback                    |
| Allowed grant types  | Authorization Code, Refresh Token *(recommended)*   |

4. Click **Finish** to redirect back to the *General Settings* of your application.
5. Copy the **Client ID**, as it will be needed for the client configuration.
6. Get your issuer, which is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, https://dev-1234.oktapreview.com/oauth2/default.

**Note:** *As with any Okta application, make sure you assign Users or Groups to the application.
          Otherwise, no one can use it.*

### Configuration

Create a file called `okta_app_auth_config.json` in your application's `res/raw/` directory with
the following contents:

```json
{
  "client_id": "{clientId}",
  "redirect_uri": "{redirectUri}",
  "end_session_redirect_uri": "{endSessionUri}",
  "scopes": [
    "openid",
    "profile",
    "offline_access"
  ],
  "issuer_uri": "https://{yourOktaDomain}/oauth2/default"
}
```

**Note**: *To receive a **refresh_token**, you must include the `offline_access` scope.*
**Note**: `end_session_redirect_uri` is a mandatory parameter.

### Update the URI Scheme

In order to redirect back to your application from a web browser, you must specify a unique URI to
your app. To do this, you must define a gradle manifest placeholder in your app's `build.gradle`:

```java
android.defaultConfig.manifestPlaceholders = [
    "appAuthRedirectScheme": "com.okta.example"
]
```

Make sure this is consistent with the redirect URI used in `okta_app_auth_config.json`. For example,
if your **Redirect URI** is `com.okta.example:/callback`, the **AppAuth Redirect Scheme** should be
`com.okta.example`.

#### Chrome Custom Tabs `ERR_UNKNOWN_URL_SCHEME`

There is a [known issue](https://github.com/okta/okta-sdk-appauth-android/issues/8) when redirecting back to a URI scheme from the browser via Chrome Custom Tabs. This is due to Chrome **not supporting** JavaScript initiated redirects back to native applications.

To handle this, the AppAuth team proposes the following:
> Create a web page for your redirect URI that displays an interstitial page with a **Click here to return to app** button. [Ian McGinniss (AppAuth-Android Author)](https://github.com/openid/AppAuth-Android/issues/187#issuecomment-285546334)

There is a working sample application referenced [here](https://github.com/iainmcgin/AppAuth-Demo), where the interstitial page is used to capture the `code` and `state` values from the callback, then redirects the user back to the private-use URI scheme specified by the application.

The flow should look similar to:
<p align="center">
  <img src="https://user-images.githubusercontent.com/20212241/38281780-4c3105dc-3761-11e8-81a5-36337b2ab39a.png" width="500px">
</p>

More information on this topic is recorded in [this issue](https://github.com/okta/okta-sdk-appauth-android/issues/8).

## Authorization

First, initialize the Okta AppAuth SDK in the `Activity#onCreate` method of the Activity that you
are using to log users into your app. In this example, we will call it `LoginActivity`:

```java
// LoginActivity.java

public class LoginActivity extends Activity {

    private OktaAppAuth mOktaAuth;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //Context must be Activity instance.
        mOktaAuth = OktaAppAuth.getInstance(this);

        // Do any of your own setup of the Activity
        mOktaAuth.init(
                this,
                new OktaAppAuth.OktaAuthListener() {
                    @Override
                    public void onSuccess() {
                        // Handle a successful initialization (e.g. display login button)
                    }

                    @Override
                    public void onTokenFailure(@NonNull AuthorizationException ex) {
                        // Handle a failed initialization
                    }
                });
    }
}
```

The Context passed in `OktaAppAuth.getInstance` must be Activity instance.

Once the OktaAppAuth instance is initialized, you can start the authorization flow by simply calling
`login` whenever you're ready:

```java
// LoginActivity.java

public class LoginActivity extends Activity {

    private void startAuth() {
        Intent completionIntent = new Intent(this, AuthorizedActivity.class);
        Intent cancelIntent = new Intent(this, LoginActivity.class);
        cancelIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);

        mOktaAuth.login(
                this,
                PendingIntent.getActivity(this, 0, completionIntent, 0),
                PendingIntent.getActivity(this, 0, cancelIntent, 0)
        );
    }
}
```

To login using a username hint, simply hookup a `LoginHintChangeHandler` to your `EditText` that has
the username input. Usually this happens in your `onCreate`:

```java
((EditText)findViewById(R.id.login_hint_value)).addTextChangedListener(
                new LoginHintChangeHandler(mOktaAuth));
```

### Get UserInfo

Once a user logs in, you can use the OktaAppAuth object to call the OIDC userInfo endpoint to return
user information.
```java
private void fetchUserInfo() {
    mOktaAuth.getUserInfo(new OktaAppAuth.OktaAuthActionCallback<JSONObject>() {
        @Override
        public void onSuccess(JSONObject response) {
            // Do whatever you need to do with the user info data
        }

        @Override
        public void onTokenFailure(@NonNull AuthorizationException ex) {
            // Handle an error with the Okta authorization and tokens
        }

        @Override
        public void onFailure(int httpResponseCode, Exception ex) {
            // Handle a network error when fetching the user info data
        }
    });
}
```

### Performing Authorized Requests

In addition to the built in userInfo endpoint, you can use the OktaAppAuth interface to perform
your own authorized requests, whatever they might be. You can use this simple method to make
your own requests and have the access token automatically added to the `Authorization` header with
the standard OAuth 2.0 prefix of `Bearer`. The `performAuthorizedRequest` method will also handle
getting new tokens for you if required:

```java
final URL myUrl; // some protected URL

mOktaAuth.performAuthorizedRequest(new OktaAppAuth.BearerAuthRequest() {
    @NonNull
    @Override
    public HttpURLConnection createRequest() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) myUrl.openConnection();
        conn.setInstanceFollowRedirects(false); // recommended during authorized calls
        return conn;
    }

    @Override
    public void onSuccess(@NonNull InputStream response) {
        // Handle successful response in the input stream
    }

    @Override
    public void onTokenFailure(@NonNull AuthorizationException ex) {
        // Handle failure to acquire new tokens from Okta
    }

    @Override
    public void onFailure(int httpResponseCode, Exception ex) {
        // Handle failure to make your authorized request or a response with a 4xx or
        // 5xx HTTP status response code
    }
);
```

### Refresh a Token Manually

You can also refresh the `accessToken` if the `refreshToken` is provided.

```java
mOktaAuth.refreshAccessToken(new OktaAuth.OktaAuthListener() {
    @Override
    public void onSuccess() {
        // Handle a successful refresh
    }

    @Override
    public void onTokenFailure(@NonNull AuthorizationException ex) {
        // Handle a failure to refresh the tokens
    }
```

### Token Management

Tokens are securely stored in the private Shared Preferences.

### End session

In order to perform end session within user's current browser and perform logout
you have to call `signOutFromOkta()` whenever you are ready

```java
// LoginActivity.java

public class UserInfoActivity extends Activity {

    private void signOutFromOkta() {
        Intent completionIntent = new Intent(this, LoginActivity.class);
        Intent cancelIntent = new Intent(this, UserInfoActivity.class);
        cancelIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);

        mOktaAuth.signOutFromOkta(
                this,
                PendingIntent.getActivity(this, 0, completionIntent, 0),
                PendingIntent.getActivity(this, 0, cancelIntent, 0)
        );
    }
}
```
### Clean up

Once authorization is done and the OktaAppAuth instance is no longer needed `dispose` must be called. For example in `LoginActivity`

```java
// LoginActivity.java
    @Override
    protected void onDestroy() {
        if (mOktaAppAuth != null) {
            mOktaAppAuth.dispose();
            mOktaAppAuth = null;
        }
        super.onDestroy();
    }
```


## License

See the LICENSE file for more info.
