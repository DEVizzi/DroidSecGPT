.class public Lcom/android/insecurebankv2/DoLogin;
.super Landroid/app/Activity;
.source "DoLogin.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/android/insecurebankv2/DoLogin$RequestTask;
    }
.end annotation


# static fields
.field public static final MYPREFS:Ljava/lang/String; = "mySharedPreferences"


# instance fields
.field password:Ljava/lang/String;

.field protocol:Ljava/lang/String;

.field reader:Ljava/io/BufferedReader;

.field rememberme_password:Ljava/lang/String;

.field rememberme_username:Ljava/lang/String;

.field responseString:Ljava/lang/String;

.field result:Ljava/lang/String;

.field serverDetails:Landroid/content/SharedPreferences;

.field serverip:Ljava/lang/String;

.field serverport:Ljava/lang/String;

.field superSecurePassword:Ljava/lang/String;

.field username:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .prologue
    .line 47
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    .line 48
    const/4 v0, 0x0

    iput-object v0, p0, Lcom/android/insecurebankv2/DoLogin;->responseString:Ljava/lang/String;

    .line 57
    const-string v0, ""

    iput-object v0, p0, Lcom/android/insecurebankv2/DoLogin;->serverip:Ljava/lang/String;

    .line 58
    const-string v0, ""

    iput-object v0, p0, Lcom/android/insecurebankv2/DoLogin;->serverport:Ljava/lang/String;

    .line 59
    const-string v0, "http://"

    iput-object v0, p0, Lcom/android/insecurebankv2/DoLogin;->protocol:Ljava/lang/String;

    .line 90
    return-void
.end method


# virtual methods
.method public callPreferences()V
    .locals 2

    .prologue
    .line 239
    new-instance v0, Landroid/content/Intent;

    const-class v1, Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 240
    .local v0, "i":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/DoLogin;->startActivity(Landroid/content/Intent;)V

    .line 241
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 6
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    const/4 v5, 0x0

    const/4 v4, 0x1

    .line 65
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 66
    const v2, 0x7f04001a

    invoke-virtual {p0, v2}, Lcom/android/insecurebankv2/DoLogin;->setContentView(I)V

    .line 67
    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoLogin;->finish()V

    .line 70
    invoke-static {p0}, Landroid/preference/PreferenceManager;->getDefaultSharedPreferences(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v2

    iput-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->serverDetails:Landroid/content/SharedPreferences;

    .line 71
    iget-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->serverDetails:Landroid/content/SharedPreferences;

    const-string v3, "serverip"

    invoke-interface {v2, v3, v5}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    iput-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->serverip:Ljava/lang/String;

    .line 72
    iget-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->serverDetails:Landroid/content/SharedPreferences;

    const-string v3, "serverport"

    invoke-interface {v2, v3, v5}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    iput-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->serverport:Ljava/lang/String;

    .line 73
    iget-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->serverip:Ljava/lang/String;

    if-eqz v2, :cond_0

    iget-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->serverport:Ljava/lang/String;

    if-eqz v2, :cond_0

    .line 75
    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoLogin;->getIntent()Landroid/content/Intent;

    move-result-object v0

    .line 76
    .local v0, "data":Landroid/content/Intent;
    const-string v2, "passed_username"

    invoke-virtual {v0, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    iput-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->username:Ljava/lang/String;

    .line 77
    const-string v2, "passed_password"

    invoke-virtual {v0, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    iput-object v2, p0, Lcom/android/insecurebankv2/DoLogin;->password:Ljava/lang/String;

    .line 78
    new-instance v2, Lcom/android/insecurebankv2/DoLogin$RequestTask;

    invoke-direct {v2, p0}, Lcom/android/insecurebankv2/DoLogin$RequestTask;-><init>(Lcom/android/insecurebankv2/DoLogin;)V

    new-array v3, v4, [Ljava/lang/String;

    const/4 v4, 0x0

    const-string v5, "username"

    aput-object v5, v3, v4

    invoke-virtual {v2, v3}, Lcom/android/insecurebankv2/DoLogin$RequestTask;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;

    .line 88
    .end local v0    # "data":Landroid/content/Intent;
    :goto_0
    return-void

    .line 83
    :cond_0
    new-instance v1, Landroid/content/Intent;

    const-class v2, Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-direct {v1, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 84
    .local v1, "setupServerdetails":Landroid/content/Intent;
    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/DoLogin;->startActivity(Landroid/content/Intent;)V

    .line 85
    const-string v2, "Server path/port not set!"

    invoke-static {p0, v2, v4}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v2

    invoke-virtual {v2}, Landroid/widget/Toast;->show()V

    goto :goto_0
.end method

.method public onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2
    .param p1, "menu"    # Landroid/view/Menu;

    .prologue
    .line 217
    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoLogin;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    const v1, 0x7f0e0002

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    .line 218
    const/4 v0, 0x1

    return v0
.end method

.method public onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 5
    .param p1, "item"    # Landroid/view/MenuItem;

    .prologue
    const/4 v2, 0x1

    .line 224
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    .line 225
    .local v1, "id":I
    const v3, 0x7f0d009d

    if-ne v1, v3, :cond_0

    .line 226
    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoLogin;->callPreferences()V

    .line 234
    :goto_0
    return v2

    .line 228
    :cond_0
    const v3, 0x7f0d009e

    if-ne v1, v3, :cond_1

    .line 229
    new-instance v0, Landroid/content/Intent;

    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoLogin;->getBaseContext()Landroid/content/Context;

    move-result-object v3

    const-class v4, Lcom/android/insecurebankv2/LoginActivity;

    invoke-direct {v0, v3, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 230
    .local v0, "i":Landroid/content/Intent;
    const/high16 v3, 0x4000000

    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 231
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/DoLogin;->startActivity(Landroid/content/Intent;)V

    goto :goto_0

    .line 234
    .end local v0    # "i":Landroid/content/Intent;
    :cond_1
    invoke-super {p0, p1}, Landroid/app/Activity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result v2

    goto :goto_0
.end method
