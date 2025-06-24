.class public Lcom/android/insecurebankv2/LoginActivity;
.super Landroid/app/Activity;
.source "LoginActivity.java"


# static fields
.field public static final MYPREFS:Ljava/lang/String; = "mySharedPreferences"


# instance fields
.field Password_Text:Landroid/widget/EditText;

.field Username_Text:Landroid/widget/EditText;

.field createuser_buttons:Landroid/widget/Button;

.field fillData_button:Landroid/widget/Button;

.field login_buttons:Landroid/widget/Button;

.field usernameBase64ByteString:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 0

    .prologue
    .line 32
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method


# virtual methods
.method public callPreferences()V
    .locals 2

    .prologue
    .line 184
    new-instance v0, Landroid/content/Intent;

    const-class v1, Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 185
    .local v0, "i":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/LoginActivity;->startActivity(Landroid/content/Intent;)V

    .line 186
    return-void
.end method

.method protected createUser()V
    .locals 2

    .prologue
    .line 98
    const-string v0, "Create User functionality is still Work-In-Progress!!"

    const/4 v1, 0x1

    invoke-static {p0, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v0

    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    .line 100
    return-void
.end method

.method protected fillData()V
    .locals 11
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;,
            Ljava/security/InvalidKeyException;,
            Ljava/security/NoSuchAlgorithmException;,
            Ljavax/crypto/NoSuchPaddingException;,
            Ljava/security/InvalidAlgorithmParameterException;,
            Ljavax/crypto/IllegalBlockSizeException;,
            Ljavax/crypto/BadPaddingException;
        }
    .end annotation

    .prologue
    const/4 v10, 0x0

    const/4 v9, 0x1

    const/4 v8, 0x0

    .line 109
    const-string v7, "mySharedPreferences"

    invoke-virtual {p0, v7, v8}, Lcom/android/insecurebankv2/LoginActivity;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v4

    .line 110
    .local v4, "settings":Landroid/content/SharedPreferences;
    const-string v7, "EncryptedUsername"

    invoke-interface {v4, v7, v10}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    .line 111
    .local v5, "username":Ljava/lang/String;
    const-string v7, "superSecurePassword"

    invoke-interface {v4, v7, v10}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    .line 114
    .local v3, "password":Ljava/lang/String;
    if-eqz v5, :cond_0

    if-eqz v3, :cond_0

    .line 116
    invoke-static {v5, v8}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v6

    .line 118
    .local v6, "usernameBase64Byte":[B
    :try_start_0
    new-instance v7, Ljava/lang/String;

    const-string v8, "UTF-8"

    invoke-direct {v7, v6, v8}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    iput-object v7, p0, Lcom/android/insecurebankv2/LoginActivity;->usernameBase64ByteString:Ljava/lang/String;
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_0

    .line 123
    :goto_0
    const v7, 0x7f0d0078

    invoke-virtual {p0, v7}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroid/widget/EditText;

    iput-object v7, p0, Lcom/android/insecurebankv2/LoginActivity;->Username_Text:Landroid/widget/EditText;

    .line 124
    const v7, 0x7f0d0079

    invoke-virtual {p0, v7}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroid/widget/EditText;

    iput-object v7, p0, Lcom/android/insecurebankv2/LoginActivity;->Password_Text:Landroid/widget/EditText;

    .line 125
    iget-object v7, p0, Lcom/android/insecurebankv2/LoginActivity;->Username_Text:Landroid/widget/EditText;

    iget-object v8, p0, Lcom/android/insecurebankv2/LoginActivity;->usernameBase64ByteString:Ljava/lang/String;

    invoke-virtual {v7, v8}, Landroid/widget/EditText;->setText(Ljava/lang/CharSequence;)V

    .line 126
    new-instance v0, Lcom/android/insecurebankv2/CryptoClass;

    invoke-direct {v0}, Lcom/android/insecurebankv2/CryptoClass;-><init>()V

    .line 127
    .local v0, "crypt":Lcom/android/insecurebankv2/CryptoClass;
    invoke-virtual {v0, v3}, Lcom/android/insecurebankv2/CryptoClass;->aesDeccryptedString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 128
    .local v1, "decryptedPassword":Ljava/lang/String;
    iget-object v7, p0, Lcom/android/insecurebankv2/LoginActivity;->Password_Text:Landroid/widget/EditText;

    invoke-virtual {v7, v1}, Landroid/widget/EditText;->setText(Ljava/lang/CharSequence;)V

    .line 139
    .end local v0    # "crypt":Lcom/android/insecurebankv2/CryptoClass;
    .end local v1    # "decryptedPassword":Ljava/lang/String;
    .end local v6    # "usernameBase64Byte":[B
    :goto_1
    return-void

    .line 119
    .restart local v6    # "usernameBase64Byte":[B
    :catch_0
    move-exception v2

    .line 121
    .local v2, "e":Ljava/io/UnsupportedEncodingException;
    invoke-virtual {v2}, Ljava/io/UnsupportedEncodingException;->printStackTrace()V

    goto :goto_0

    .line 130
    .end local v2    # "e":Ljava/io/UnsupportedEncodingException;
    .end local v6    # "usernameBase64Byte":[B
    :cond_0
    if-eqz v5, :cond_1

    if-nez v3, :cond_2

    .line 132
    :cond_1
    const-string v7, "No stored credentials found!!"

    invoke-static {p0, v7, v9}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v7

    invoke-virtual {v7}, Landroid/widget/Toast;->show()V

    goto :goto_1

    .line 136
    :cond_2
    const-string v7, "No stored credentials found!!"

    invoke-static {p0, v7, v9}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v7

    invoke-virtual {v7}, Landroid/widget/Toast;->show()V

    goto :goto_1
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 5
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    const v4, 0x7f0d006e

    .line 49
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 50
    const v2, 0x7f04001d

    invoke-virtual {p0, v2}, Lcom/android/insecurebankv2/LoginActivity;->setContentView(I)V

    .line 51
    invoke-virtual {p0}, Lcom/android/insecurebankv2/LoginActivity;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    const v3, 0x7f07004a

    invoke-virtual {v2, v3}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object v1

    .line 52
    .local v1, "mess":Ljava/lang/String;
    const-string v2, "no"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    .line 53
    invoke-virtual {p0, v4}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    .line 54
    .local v0, "button_CreateUser":Landroid/view/View;
    const/16 v2, 0x8

    invoke-virtual {v0, v2}, Landroid/view/View;->setVisibility(I)V

    .line 56
    .end local v0    # "button_CreateUser":Landroid/view/View;
    :cond_0
    const v2, 0x7f0d007a

    invoke-virtual {p0, v2}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroid/widget/Button;

    iput-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->login_buttons:Landroid/widget/Button;

    .line 57
    iget-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->login_buttons:Landroid/widget/Button;

    new-instance v3, Lcom/android/insecurebankv2/LoginActivity$1;

    invoke-direct {v3, p0}, Lcom/android/insecurebankv2/LoginActivity$1;-><init>(Lcom/android/insecurebankv2/LoginActivity;)V

    invoke-virtual {v2, v3}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 65
    invoke-virtual {p0, v4}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroid/widget/Button;

    iput-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->createuser_buttons:Landroid/widget/Button;

    .line 66
    iget-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->createuser_buttons:Landroid/widget/Button;

    new-instance v3, Lcom/android/insecurebankv2/LoginActivity$2;

    invoke-direct {v3, p0}, Lcom/android/insecurebankv2/LoginActivity$2;-><init>(Lcom/android/insecurebankv2/LoginActivity;)V

    invoke-virtual {v2, v3}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 74
    const v2, 0x7f0d007b

    invoke-virtual {p0, v2}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroid/widget/Button;

    iput-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->fillData_button:Landroid/widget/Button;

    .line 75
    iget-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->fillData_button:Landroid/widget/Button;

    new-instance v3, Lcom/android/insecurebankv2/LoginActivity$3;

    invoke-direct {v3, p0}, Lcom/android/insecurebankv2/LoginActivity$3;-><init>(Lcom/android/insecurebankv2/LoginActivity;)V

    invoke-virtual {v2, v3}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 89
    return-void
.end method

.method public onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2
    .param p1, "menu"    # Landroid/view/Menu;

    .prologue
    .line 159
    invoke-virtual {p0}, Lcom/android/insecurebankv2/LoginActivity;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    const v1, 0x7f0e0002

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    .line 160
    const/4 v0, 0x1

    return v0
.end method

.method public onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 5
    .param p1, "item"    # Landroid/view/MenuItem;

    .prologue
    const/4 v2, 0x1

    .line 169
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    .line 170
    .local v1, "id":I
    const v3, 0x7f0d009d

    if-ne v1, v3, :cond_0

    .line 171
    invoke-virtual {p0}, Lcom/android/insecurebankv2/LoginActivity;->callPreferences()V

    .line 179
    :goto_0
    return v2

    .line 173
    :cond_0
    const v3, 0x7f0d009e

    if-ne v1, v3, :cond_1

    .line 174
    new-instance v0, Landroid/content/Intent;

    invoke-virtual {p0}, Lcom/android/insecurebankv2/LoginActivity;->getBaseContext()Landroid/content/Context;

    move-result-object v3

    const-class v4, Lcom/android/insecurebankv2/LoginActivity;

    invoke-direct {v0, v3, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 175
    .local v0, "i":Landroid/content/Intent;
    const/high16 v3, 0x4000000

    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 176
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/LoginActivity;->startActivity(Landroid/content/Intent;)V

    goto :goto_0

    .line 179
    .end local v0    # "i":Landroid/content/Intent;
    :cond_1
    invoke-super {p0, p1}, Landroid/app/Activity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result v2

    goto :goto_0
.end method

.method protected performlogin()V
    .locals 3

    .prologue
    .line 148
    const v1, 0x7f0d0078

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/EditText;

    iput-object v1, p0, Lcom/android/insecurebankv2/LoginActivity;->Username_Text:Landroid/widget/EditText;

    .line 149
    const v1, 0x7f0d0079

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/LoginActivity;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/EditText;

    iput-object v1, p0, Lcom/android/insecurebankv2/LoginActivity;->Password_Text:Landroid/widget/EditText;

    .line 150
    new-instance v0, Landroid/content/Intent;

    const-class v1, Lcom/android/insecurebankv2/DoLogin;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 151
    .local v0, "i":Landroid/content/Intent;
    const-string v1, "passed_username"

    iget-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->Username_Text:Landroid/widget/EditText;

    invoke-virtual {v2}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 152
    const-string v1, "passed_password"

    iget-object v2, p0, Lcom/android/insecurebankv2/LoginActivity;->Password_Text:Landroid/widget/EditText;

    invoke-virtual {v2}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 153
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/LoginActivity;->startActivity(Landroid/content/Intent;)V

    .line 154
    return-void
.end method
