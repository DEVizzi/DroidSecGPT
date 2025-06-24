package com.android.insecurebankv2;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;
/* loaded from: classes.dex */
public class DoLogin extends Activity {
    public static final String MYPREFS = "mySharedPreferences";
    String password;
    BufferedReader reader;
    String rememberme_password;
    String rememberme_username;
    String result;
    SharedPreferences serverDetails;
    String superSecurePassword;
    String username;
    String responseString = null;
    String serverip = "";
    String serverport = "";
    String protocol = "http://";

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_do_login);
        finish();
        this.serverDetails = PreferenceManager.getDefaultSharedPreferences(this);
        this.serverip = this.serverDetails.getString("serverip", null);
        this.serverport = this.serverDetails.getString("serverport", null);
        if (this.serverip != null && this.serverport != null) {
            Intent data = getIntent();
            this.username = data.getStringExtra("passed_username");
            this.password = data.getStringExtra("passed_password");
            new RequestTask().execute("username");
            return;
        }
        Intent setupServerdetails = new Intent(this, FilePrefActivity.class);
        startActivity(setupServerdetails);
        Toast.makeText(this, "Server path/port not set!", 1).show();
    }

    /* loaded from: classes.dex */
    class RequestTask extends AsyncTask<String, String, String> {
        RequestTask() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public String doInBackground(String... params) {
            try {
                postData(params[0]);
                return null;
            } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | JSONException e) {
                e.printStackTrace();
                return null;
            }
        }

        protected void onPostExecute(Double result) {
        }

        protected void onProgressUpdate(Integer... progress) {
        }

        public void postData(String valueIWantToSend) throws ClientProtocolException, IOException, JSONException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
            HttpResponse responseBody;
            DefaultHttpClient defaultHttpClient = new DefaultHttpClient();
            HttpPost httppost = new HttpPost(DoLogin.this.protocol + DoLogin.this.serverip + ":" + DoLogin.this.serverport + "/login");
            HttpPost httppost2 = new HttpPost(DoLogin.this.protocol + DoLogin.this.serverip + ":" + DoLogin.this.serverport + "/devlogin");
            List<NameValuePair> nameValuePairs = new ArrayList<>(2);
            nameValuePairs.add(new BasicNameValuePair("username", DoLogin.this.username));
            nameValuePairs.add(new BasicNameValuePair("password", DoLogin.this.password));
            if (DoLogin.this.username.equals("devadmin")) {
                httppost2.setEntity(new UrlEncodedFormEntity(nameValuePairs));
                responseBody = defaultHttpClient.execute(httppost2);
            } else {
                httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
                responseBody = defaultHttpClient.execute(httppost);
            }
            InputStream in = responseBody.getEntity().getContent();
            DoLogin.this.result = convertStreamToString(in);
            DoLogin.this.result = DoLogin.this.result.replace("\n", "");
            if (DoLogin.this.result != null) {
                if (DoLogin.this.result.indexOf("Correct Credentials") != -1) {
                    Log.d("Successful Login:", ", account=" + DoLogin.this.username + ":" + DoLogin.this.password);
                    saveCreds(DoLogin.this.username, DoLogin.this.password);
                    trackUserLogins();
                    Intent pL = new Intent(DoLogin.this.getApplicationContext(), PostLogin.class);
                    pL.putExtra("uname", DoLogin.this.username);
                    DoLogin.this.startActivity(pL);
                    return;
                }
                Intent xi = new Intent(DoLogin.this.getApplicationContext(), WrongLogin.class);
                DoLogin.this.startActivity(xi);
            }
        }

        private void trackUserLogins() {
            DoLogin.this.runOnUiThread(new Runnable() { // from class: com.android.insecurebankv2.DoLogin.RequestTask.1
                @Override // java.lang.Runnable
                public void run() {
                    ContentValues values = new ContentValues();
                    values.put("name", DoLogin.this.username);
                    DoLogin.this.getContentResolver().insert(TrackUserContentProvider.CONTENT_URI, values);
                }
            });
        }

        private void saveCreds(String username, String password) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
            SharedPreferences mySharedPreferences = DoLogin.this.getSharedPreferences("mySharedPreferences", 0);
            SharedPreferences.Editor editor = mySharedPreferences.edit();
            DoLogin.this.rememberme_username = username;
            DoLogin.this.rememberme_password = password;
            String base64Username = new String(Base64.encodeToString(DoLogin.this.rememberme_username.getBytes(), 4));
            CryptoClass crypt = new CryptoClass();
            DoLogin.this.superSecurePassword = crypt.aesEncryptedString(DoLogin.this.rememberme_password);
            editor.putString("EncryptedUsername", base64Username);
            editor.putString("superSecurePassword", DoLogin.this.superSecurePassword);
            editor.commit();
        }

        private String convertStreamToString(InputStream in) throws IOException {
            try {
                DoLogin.this.reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            StringBuilder sb = new StringBuilder();
            while (true) {
                String line = DoLogin.this.reader.readLine();
                if (line != null) {
                    sb.append(line + "\n");
                } else {
                    in.close();
                    return sb.toString();
                }
            }
        }
    }

    @Override // android.app.Activity
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override // android.app.Activity
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            callPreferences();
            return true;
        } else if (id == R.id.action_exit) {
            Intent i = new Intent(getBaseContext(), LoginActivity.class);
            i.addFlags(67108864);
            startActivity(i);
            return true;
        } else {
            return super.onOptionsItemSelected(item);
        }
    }

    public void callPreferences() {
        Intent i = new Intent(this, FilePrefActivity.class);
        startActivity(i);
    }
}
