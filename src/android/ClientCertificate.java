package org.apache.cordova.plugin.clientcert;

import android.annotation.TargetApi;
import android.os.Build;
import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificate extends CordovaPlugin {

    private String p12FileName = "";
    private String p12Password = "";

    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(null);
//            android.util.Log.v("chromium", "FilesDir: " + new File(cordova.getActivity().getApplicationContext().getFilesDir(),
//                    p12FileName).toString());

            InputStream astream = new FileInputStream(new File(cordova.getActivity().getApplicationContext().getFilesDir(),
                    p12FileName));
            keystore.load(astream, p12Password.toCharArray());
            astream.close();
            Enumeration e = keystore.aliases();
            if (e.hasMoreElements()) {
                String ealias = (String) e.nextElement();
                PrivateKey key = (PrivateKey) keystore.getKey(ealias, p12Password.toCharArray());
                java.security.cert.Certificate[] chain = keystore.getCertificateChain(ealias);
                X509Certificate[] certs = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
                request.proceed(key, certs);
//                android.util.Log.v("chromium", "request proceeded");
            } else {
                request.ignore();
//                android.util.Log.v("chromium", "request ignored");
            }
        } catch (Exception ex) {
//            android.util.Log.v("chromium", "Exception in client-certificate plugin happened.");
            ex.printStackTrace();
            request.ignore();
        }
        return true;
    }

    @Override
    public boolean execute(String action, JSONArray a, CallbackContext c) throws JSONException {
        if (action.equals("registerAuthenticationCertificate")) {
            p12FileName = a.getString(0);
            p12Password = a.getString(1);
            return true;
        }
        return false;
    }
}