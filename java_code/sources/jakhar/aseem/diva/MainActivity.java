package jakhar.aseem.diva;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
    }

    @Override // android.app.Activity
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override // android.app.Activity
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void startChallenge(View view) {
        if (view == findViewById(R.id.d1button)) {
            Intent i = new Intent(this, LogActivity.class);
            startActivity(i);
        } else if (view == findViewById(R.id.d2button)) {
            Intent i2 = new Intent(this, HardcodeActivity.class);
            startActivity(i2);
        } else if (view == findViewById(R.id.d3button)) {
            Intent i3 = new Intent(this, InsecureDataStorage1Activity.class);
            startActivity(i3);
        } else if (view == findViewById(R.id.d4button)) {
            Intent i4 = new Intent(this, InsecureDataStorage2Activity.class);
            startActivity(i4);
        } else if (view == findViewById(R.id.d5button)) {
            Intent i5 = new Intent(this, InsecureDataStorage3Activity.class);
            startActivity(i5);
        } else if (view == findViewById(R.id.d6button)) {
            Intent i6 = new Intent(this, InsecureDataStorage4Activity.class);
            startActivity(i6);
        } else if (view == findViewById(R.id.d7button)) {
            Intent i7 = new Intent(this, SQLInjectionActivity.class);
            startActivity(i7);
        } else if (view == findViewById(R.id.d8button)) {
            Intent i8 = new Intent(this, InputValidation2URISchemeActivity.class);
            startActivity(i8);
        } else if (view == findViewById(R.id.d9button)) {
            Intent i9 = new Intent(this, AccessControl1Activity.class);
            startActivity(i9);
        } else if (view == findViewById(R.id.d10button)) {
            Intent i10 = new Intent(this, AccessControl2Activity.class);
            startActivity(i10);
        } else if (view == findViewById(R.id.d11button)) {
            Intent i11 = new Intent(this, AccessControl3Activity.class);
            startActivity(i11);
        } else if (view == findViewById(R.id.d12button)) {
            Intent i12 = new Intent(this, Hardcode2Activity.class);
            startActivity(i12);
        } else if (view == findViewById(R.id.d13button)) {
            Intent i13 = new Intent(this, InputValidation3Activity.class);
            startActivity(i13);
        }
    }
}
