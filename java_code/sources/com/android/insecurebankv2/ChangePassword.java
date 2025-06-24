package com.android.insecurebankv2;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import org.json.JSONObject;
/* loaded from: classes.dex */
public class ChangePassword extends Activity {
    private static final String PASSWORD_PATTERN = "((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})";
    Button changePassword_button;
    EditText changePassword_text;
    private Matcher matcher;
    private Pattern pattern;
    BufferedReader reader;
    String result;
    SharedPreferences serverDetails;
    TextView textView_Username;
    String uname;
    String serverip = "";
    String serverport = "";
    String protocol = "http://";

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_change_password);
        this.serverDetails = PreferenceManager.getDefaultSharedPreferences(this);
        this.serverip = this.serverDetails.getString("serverip", null);
        this.serverport = this.serverDetails.getString("serverport", null);
        this.changePassword_text = (EditText) findViewById(R.id.editText_newPassword);
        Intent intent = getIntent();
        this.uname = intent.getStringExtra("uname");
        System.out.println("newpassword=" + this.uname);
        this.textView_Username = (TextView) findViewById(R.id.textView_Username);
        this.textView_Username.setText(this.uname);
        this.changePassword_button = (Button) findViewById(R.id.button_newPasswordSubmit);
        this.changePassword_button.setOnClickListener(new View.OnClickListener() { // from class: com.android.insecurebankv2.ChangePassword.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                new RequestChangePasswordTask().execute(ChangePassword.this.uname);
            }
        });
    }

    /* loaded from: classes.dex */
    class RequestChangePasswordTask extends AsyncTask<String, String, String> {
        RequestChangePasswordTask() {
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
            DefaultHttpClient defaultHttpClient = new DefaultHttpClient();
            HttpPost httppost = new HttpPost(ChangePassword.this.protocol + ChangePassword.this.serverip + ":" + ChangePassword.this.serverport + "/changepassword");
            List<NameValuePair> nameValuePairs = new ArrayList<>(2);
            nameValuePairs.add(new BasicNameValuePair("username", ChangePassword.this.uname));
            nameValuePairs.add(new BasicNameValuePair("newpassword", ChangePassword.this.changePassword_text.getText().toString()));
            httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            ChangePassword.this.pattern = Pattern.compile(ChangePassword.PASSWORD_PATTERN);
            ChangePassword.this.matcher = ChangePassword.this.pattern.matcher(ChangePassword.this.changePassword_text.getText().toString());
            boolean isStrong = ChangePassword.this.matcher.matches();
            if (isStrong) {
                HttpResponse responseBody = defaultHttpClient.execute(httppost);
                InputStream in = responseBody.getEntity().getContent();
                ChangePassword.this.result = convertStreamToString(in);
                ChangePassword.this.result = ChangePassword.this.result.replace("\n", "");
                ChangePassword.this.runOnUiThread(new Runnable() { // from class: com.android.insecurebankv2.ChangePassword.RequestChangePasswordTask.1
                    @Override // java.lang.Runnable
                    public void run() {
                        if (ChangePassword.this.result != null && ChangePassword.this.result.indexOf("Change Password Successful") != -1) {
                            try {
                                JSONObject jsonObject = new JSONObject(ChangePassword.this.result);
                                String login_response_message = jsonObject.getString("message");
                                Toast.makeText(ChangePassword.this.getApplicationContext(), login_response_message + ". Restart application to Continue.", 1).show();
                                TelephonyManager phoneManager = (TelephonyManager) ChangePassword.this.getApplicationContext().getSystemService("phone");
                                String phoneNumber = phoneManager.getLine1Number();
                                System.out.println("phonno:" + phoneNumber);
                                ChangePassword.this.broadcastChangepasswordSMS(phoneNumber, ChangePassword.this.changePassword_text.getText().toString());
                            } catch (JSONException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                });
                return;
            }
            ChangePassword.this.runOnUiThread(new Runnable() { // from class: com.android.insecurebankv2.ChangePassword.RequestChangePasswordTask.2
                @Override // java.lang.Runnable
                public void run() {
                    Toast.makeText(ChangePassword.this.getApplicationContext(), "Entered password is not complex enough.", 1).show();
                }
            });
        }

        private String convertStreamToString(InputStream in) throws IOException {
            try {
                ChangePassword.this.reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            StringBuilder sb = new StringBuilder();
            while (true) {
                String line = ChangePassword.this.reader.readLine();
                if (line != null) {
                    sb.append(line + "\n");
                } else {
                    in.close();
                    return sb.toString();
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void broadcastChangepasswordSMS(String phoneNumber, String pass) {
        if (TextUtils.isEmpty(phoneNumber.toString().trim())) {
            System.out.println("Phone number Invalid.");
            return;
        }
        Intent smsIntent = new Intent();
        smsIntent.setAction("theBroadcast");
        smsIntent.putExtra("phonenumber", phoneNumber);
        smsIntent.putExtra("newpass", pass);
        sendBroadcast(smsIntent);
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
