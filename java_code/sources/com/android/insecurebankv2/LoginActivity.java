package com.android.insecurebankv2;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
/* loaded from: classes.dex */
public class LoginActivity extends Activity {
    public static final String MYPREFS = "mySharedPreferences";
    EditText Password_Text;
    EditText Username_Text;
    Button createuser_buttons;
    Button fillData_button;
    Button login_buttons;
    String usernameBase64ByteString;

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_log_main);
        String mess = getResources().getString(R.string.is_admin);
        if (mess.equals("no")) {
            View button_CreateUser = findViewById(R.id.button_CreateUser);
            button_CreateUser.setVisibility(8);
        }
        this.login_buttons = (Button) findViewById(R.id.login_button);
        this.login_buttons.setOnClickListener(new View.OnClickListener() { // from class: com.android.insecurebankv2.LoginActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                LoginActivity.this.performlogin();
            }
        });
        this.createuser_buttons = (Button) findViewById(R.id.button_CreateUser);
        this.createuser_buttons.setOnClickListener(new View.OnClickListener() { // from class: com.android.insecurebankv2.LoginActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                LoginActivity.this.createUser();
            }
        });
        this.fillData_button = (Button) findViewById(R.id.fill_data);
        this.fillData_button.setOnClickListener(new View.OnClickListener() { // from class: com.android.insecurebankv2.LoginActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                try {
                    LoginActivity.this.fillData();
                } catch (UnsupportedEncodingException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    protected void createUser() {
        Toast.makeText(this, "Create User functionality is still Work-In-Progress!!", 1).show();
    }

    protected void fillData() throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SharedPreferences settings = getSharedPreferences("mySharedPreferences", 0);
        String username = settings.getString("EncryptedUsername", null);
        String password = settings.getString("superSecurePassword", null);
        if (username != null && password != null) {
            byte[] usernameBase64Byte = Base64.decode(username, 0);
            try {
                this.usernameBase64ByteString = new String(usernameBase64Byte, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            this.Username_Text = (EditText) findViewById(R.id.loginscreen_username);
            this.Password_Text = (EditText) findViewById(R.id.loginscreen_password);
            this.Username_Text.setText(this.usernameBase64ByteString);
            CryptoClass crypt = new CryptoClass();
            String decryptedPassword = crypt.aesDeccryptedString(password);
            this.Password_Text.setText(decryptedPassword);
        } else if (username == null || password == null) {
            Toast.makeText(this, "No stored credentials found!!", 1).show();
        } else {
            Toast.makeText(this, "No stored credentials found!!", 1).show();
        }
    }

    protected void performlogin() {
        this.Username_Text = (EditText) findViewById(R.id.loginscreen_username);
        this.Password_Text = (EditText) findViewById(R.id.loginscreen_password);
        Intent i = new Intent(this, DoLogin.class);
        i.putExtra("passed_username", this.Username_Text.getText().toString());
        i.putExtra("passed_password", this.Password_Text.getText().toString());
        startActivity(i);
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
