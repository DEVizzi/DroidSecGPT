.class public Lcom/android/insecurebankv2/ChangePassword;
.super Landroid/app/Activity;
.source "ChangePassword.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;
    }
.end annotation


# static fields
.field private static final PASSWORD_PATTERN:Ljava/lang/String; = "((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})"


# instance fields
.field changePassword_button:Landroid/widget/Button;

.field changePassword_text:Landroid/widget/EditText;

.field private matcher:Ljava/util/regex/Matcher;

.field private pattern:Ljava/util/regex/Pattern;

.field protocol:Ljava/lang/String;

.field reader:Ljava/io/BufferedReader;

.field result:Ljava/lang/String;

.field serverDetails:Landroid/content/SharedPreferences;

.field serverip:Ljava/lang/String;

.field serverport:Ljava/lang/String;

.field textView_Username:Landroid/widget/TextView;

.field uname:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .prologue
    .line 53
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    .line 68
    const-string v0, ""

    iput-object v0, p0, Lcom/android/insecurebankv2/ChangePassword;->serverip:Ljava/lang/String;

    .line 69
    const-string v0, ""

    iput-object v0, p0, Lcom/android/insecurebankv2/ChangePassword;->serverport:Ljava/lang/String;

    .line 70
    const-string v0, "http://"

    iput-object v0, p0, Lcom/android/insecurebankv2/ChangePassword;->protocol:Ljava/lang/String;

    .line 101
    return-void
.end method

.method static synthetic access$000(Lcom/android/insecurebankv2/ChangePassword;)Ljava/util/regex/Pattern;
    .locals 1
    .param p0, "x0"    # Lcom/android/insecurebankv2/ChangePassword;

    .prologue
    .line 53
    iget-object v0, p0, Lcom/android/insecurebankv2/ChangePassword;->pattern:Ljava/util/regex/Pattern;

    return-object v0
.end method

.method static synthetic access$002(Lcom/android/insecurebankv2/ChangePassword;Ljava/util/regex/Pattern;)Ljava/util/regex/Pattern;
    .locals 0
    .param p0, "x0"    # Lcom/android/insecurebankv2/ChangePassword;
    .param p1, "x1"    # Ljava/util/regex/Pattern;

    .prologue
    .line 53
    iput-object p1, p0, Lcom/android/insecurebankv2/ChangePassword;->pattern:Ljava/util/regex/Pattern;

    return-object p1
.end method

.method static synthetic access$100(Lcom/android/insecurebankv2/ChangePassword;)Ljava/util/regex/Matcher;
    .locals 1
    .param p0, "x0"    # Lcom/android/insecurebankv2/ChangePassword;

    .prologue
    .line 53
    iget-object v0, p0, Lcom/android/insecurebankv2/ChangePassword;->matcher:Ljava/util/regex/Matcher;

    return-object v0
.end method

.method static synthetic access$102(Lcom/android/insecurebankv2/ChangePassword;Ljava/util/regex/Matcher;)Ljava/util/regex/Matcher;
    .locals 0
    .param p0, "x0"    # Lcom/android/insecurebankv2/ChangePassword;
    .param p1, "x1"    # Ljava/util/regex/Matcher;

    .prologue
    .line 53
    iput-object p1, p0, Lcom/android/insecurebankv2/ChangePassword;->matcher:Ljava/util/regex/Matcher;

    return-object p1
.end method

.method static synthetic access$200(Lcom/android/insecurebankv2/ChangePassword;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    .param p0, "x0"    # Lcom/android/insecurebankv2/ChangePassword;
    .param p1, "x1"    # Ljava/lang/String;
    .param p2, "x2"    # Ljava/lang/String;

    .prologue
    .line 53
    invoke-direct {p0, p1, p2}, Lcom/android/insecurebankv2/ChangePassword;->broadcastChangepasswordSMS(Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method private broadcastChangepasswordSMS(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    .param p1, "phoneNumber"    # Ljava/lang/String;
    .param p2, "pass"    # Ljava/lang/String;

    .prologue
    .line 216
    invoke-virtual {p1}, Ljava/lang/String;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_0

    .line 218
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "Phone number Invalid."

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 229
    :goto_0
    return-void

    .line 222
    :cond_0
    new-instance v0, Landroid/content/Intent;

    invoke-direct {v0}, Landroid/content/Intent;-><init>()V

    .line 223
    .local v0, "smsIntent":Landroid/content/Intent;
    const-string v1, "theBroadcast"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 224
    const-string v1, "phonenumber"

    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 225
    const-string v1, "newpass"

    invoke-virtual {v0, v1, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 226
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/ChangePassword;->sendBroadcast(Landroid/content/Intent;)V

    goto :goto_0
.end method


# virtual methods
.method public callPreferences()V
    .locals 2

    .prologue
    .line 261
    new-instance v0, Landroid/content/Intent;

    const-class v1, Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 262
    .local v0, "i":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/ChangePassword;->startActivity(Landroid/content/Intent;)V

    .line 263
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    const/4 v3, 0x0

    .line 75
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 76
    const v1, 0x7f040019

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/ChangePassword;->setContentView(I)V

    .line 79
    invoke-static {p0}, Landroid/preference/PreferenceManager;->getDefaultSharedPreferences(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->serverDetails:Landroid/content/SharedPreferences;

    .line 80
    iget-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->serverDetails:Landroid/content/SharedPreferences;

    const-string v2, "serverip"

    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->serverip:Ljava/lang/String;

    .line 81
    iget-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->serverDetails:Landroid/content/SharedPreferences;

    const-string v2, "serverport"

    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->serverport:Ljava/lang/String;

    .line 83
    const v1, 0x7f0d0067

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/ChangePassword;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/EditText;

    iput-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->changePassword_text:Landroid/widget/EditText;

    .line 84
    invoke-virtual {p0}, Lcom/android/insecurebankv2/ChangePassword;->getIntent()Landroid/content/Intent;

    move-result-object v0

    .line 85
    .local v0, "intent":Landroid/content/Intent;
    const-string v1, "uname"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->uname:Ljava/lang/String;

    .line 86
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "newpassword="

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    iget-object v3, p0, Lcom/android/insecurebankv2/ChangePassword;->uname:Ljava/lang/String;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 87
    const v1, 0x7f0d0066

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/ChangePassword;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/TextView;

    iput-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->textView_Username:Landroid/widget/TextView;

    .line 88
    iget-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->textView_Username:Landroid/widget/TextView;

    iget-object v2, p0, Lcom/android/insecurebankv2/ChangePassword;->uname:Ljava/lang/String;

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 91
    const v1, 0x7f0d0068

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/ChangePassword;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/Button;

    iput-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->changePassword_button:Landroid/widget/Button;

    .line 92
    iget-object v1, p0, Lcom/android/insecurebankv2/ChangePassword;->changePassword_button:Landroid/widget/Button;

    new-instance v2, Lcom/android/insecurebankv2/ChangePassword$1;

    invoke-direct {v2, p0}, Lcom/android/insecurebankv2/ChangePassword$1;-><init>(Lcom/android/insecurebankv2/ChangePassword;)V

    invoke-virtual {v1, v2}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 100
    return-void
.end method

.method public onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2
    .param p1, "menu"    # Landroid/view/Menu;

    .prologue
    .line 236
    invoke-virtual {p0}, Lcom/android/insecurebankv2/ChangePassword;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    const v1, 0x7f0e0002

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    .line 237
    const/4 v0, 0x1

    return v0
.end method

.method public onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 5
    .param p1, "item"    # Landroid/view/MenuItem;

    .prologue
    const/4 v2, 0x1

    .line 246
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    .line 247
    .local v1, "id":I
    const v3, 0x7f0d009d

    if-ne v1, v3, :cond_0

    .line 248
    invoke-virtual {p0}, Lcom/android/insecurebankv2/ChangePassword;->callPreferences()V

    .line 256
    :goto_0
    return v2

    .line 250
    :cond_0
    const v3, 0x7f0d009e

    if-ne v1, v3, :cond_1

    .line 251
    new-instance v0, Landroid/content/Intent;

    invoke-virtual {p0}, Lcom/android/insecurebankv2/ChangePassword;->getBaseContext()Landroid/content/Context;

    move-result-object v3

    const-class v4, Lcom/android/insecurebankv2/LoginActivity;

    invoke-direct {v0, v3, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 252
    .local v0, "i":Landroid/content/Intent;
    const/high16 v3, 0x4000000

    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 253
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/ChangePassword;->startActivity(Landroid/content/Intent;)V

    goto :goto_0

    .line 256
    .end local v0    # "i":Landroid/content/Intent;
    :cond_1
    invoke-super {p0, p1}, Landroid/app/Activity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result v2

    goto :goto_0
.end method
