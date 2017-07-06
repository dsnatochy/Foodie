package com.wps.foodie;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Map;

import co.poynt.api.model.TokenResponse;
import co.poynt.os.model.Intents;
import co.poynt.os.model.PoyntError;
import co.poynt.os.services.v1.IPoyntTokenService;
import co.poynt.os.services.v1.IPoyntTokenServiceListener;

public class MainActivity extends Activity {


    private static final String TAG = MainActivity.class.getName();
    // the app id issued to you when you upload the apk to poynt.net
    // add it to src/main/assets/config.properties (on Android Studio)
    private String appId = "urn:aid:4bb016c0-8d2b-408c-b8ef-e9958f216a2e";
    private SignedJWT signedJWT;

    private IPoyntTokenService tokenService;

    private ServiceConnection tokenServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
            tokenService = IPoyntTokenService.Stub.asInterface(iBinder);
            Log.d(TAG, "onServiceConnected ");
            try {
                tokenService.grantToken(appId, tokenServiceListener);
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName componentName) {
            Log.d(TAG, "onServiceDisconnected ");
        }
    };

    private IPoyntTokenServiceListener tokenServiceListener = new IPoyntTokenServiceListener.Stub() {
        @Override
        public void onResponse(TokenResponse tokenResponse, PoyntError poyntError) throws RemoteException {
            if (tokenResponse != null) {
                Log.d(TAG, "onResponse " + tokenResponse.getAccessToken());
                String accessToken = tokenResponse.getAccessToken();
                try {
                    signedJWT = SignedJWT.parse(accessToken);

                    // JWSVerifier verifier
                    StringBuilder claimsBuffer = new StringBuilder();
                    ReadOnlyJWTClaimsSet claims = signedJWT.getJWTClaimsSet();

                    claimsBuffer.append("Subject: " + claims.getSubject())
                            .append("\nType: " + claims.getType())
                            .append("\nIssuer: " + claims.getIssuer())
                            .append("\nJWT ID: " + claims.getJWTID())
                            .append("\nIssueTime : " + claims.getIssueTime())
                            .append("\nExpiration Time: " + claims.getExpirationTime())
                            .append("\nNot Before Time: " + claims.getNotBeforeTime());
                    for (String audience : claims.getAudience()) {
                        claimsBuffer.append("\nAudience: " + audience);
                    }

                    Map<String, Object> customClaims = claims.getCustomClaims();
                    for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                        String key = entry.getKey();
                        switch (key) {
                            case "poynt.did":
                                key += " (Device ID)";
                                break;
                            case "poynt.biz":
                                key += " (Business ID)";
                                break;
                            case "poynt.ist":
                                key += " (Issued To)";
                                break;
                            case "poynt.sct":
                                key += " (Subject Credential Type [J=JWT, E=EMAIL, U=USERNAME])";
                                break;
                            case "poynt.str":
                                key += " (Store ID)";
                                break;
                            case "poynt.kid":
                                key += " (Key ID)";
                                break;
                            default:
                                break;
                        }

                        claimsBuffer.append("\n" + key + ": " + entry.getValue());
                    }
                    final String claimsStr = claimsBuffer.toString();
                    Log.d(TAG, "claims: " + claimsStr);

                } catch (ParseException e) {
                    e.printStackTrace();
                }

            } else if (poyntError != null) {
                Log.d(TAG, "onResponse error" + poyntError.getData());
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(com.wps.foodie.R.layout.activity_main);

    }

    @Override
    protected void onResume() {
        super.onResume();
        bindService(Intents.getComponentIntent(Intents.COMPONENT_POYNT_TOKEN_SERVICE),
                tokenServiceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onPause() {
        super.onPause();
        unbindService(tokenServiceConnection);
    }


}
