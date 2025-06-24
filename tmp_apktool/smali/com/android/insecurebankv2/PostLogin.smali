.class public Lcom/android/insecurebankv2/PostLogin;
.super Landroid/app/Activity;
.source "PostLogin.java"


# instance fields
.field changepasswd_button:Landroid/widget/Button;

.field root_status:Landroid/widget/TextView;

.field statement_button:Landroid/widget/Button;

.field transfer_button:Landroid/widget/Button;

.field uname:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 0

    .prologue
    .line 28
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method

.method private doesSUexist()Z
    .locals 9

    .prologue
    const/4 v3, 0x1

    const/4 v4, 0x0

    .line 99
    const/4 v1, 0x0

    .line 101
    .local v1, "process":Ljava/lang/Process;
    :try_start_0
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v5

    const/4 v6, 0x2

    new-array v6, v6, [Ljava/lang/String;

    const/4 v7, 0x0

    const-string v8, "/system/xbin/which"

    aput-object v8, v6, v7

    const/4 v7, 0x1

    const-string v8, "su"

    aput-object v8, v6, v7

    invoke-virtual {v5, v6}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v1

    .line 102
    new-instance v0, Ljava/io/BufferedReader;

    new-instance v5, Ljava/io/InputStreamReader;

    invoke-virtual {v1}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    move-result-object v6

    invoke-direct {v5, v6}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v0, v5}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 103
    .local v0, "in":Ljava/io/BufferedReader;
    invoke-virtual {v0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-result-object v5

    if-eqz v5, :cond_1

    .line 108
    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/lang/Process;->destroy()V

    .end local v0    # "in":Ljava/io/BufferedReader;
    :cond_0
    :goto_0
    return v3

    .restart local v0    # "in":Ljava/io/BufferedReader;
    :cond_1
    if-eqz v1, :cond_2

    invoke-virtual {v1}, Ljava/lang/Process;->destroy()V

    :cond_2
    move v3, v4

    goto :goto_0

    .line 105
    .end local v0    # "in":Ljava/io/BufferedReader;
    :catch_0
    move-exception v2

    .line 108
    .local v2, "t":Ljava/lang/Throwable;
    if-eqz v1, :cond_3

    invoke-virtual {v1}, Ljava/lang/Process;->destroy()V

    :cond_3
    move v3, v4

    goto :goto_0

    .end local v2    # "t":Ljava/lang/Throwable;
    :catchall_0
    move-exception v3

    if-eqz v1, :cond_4

    invoke-virtual {v1}, Ljava/lang/Process;->destroy()V

    :cond_4
    throw v3
.end method

.method private doesSuperuserApkExist(Ljava/lang/String;)Z
    .locals 4
    .param p1, "s"    # Ljava/lang/String;

    .prologue
    const/4 v2, 0x1

    .line 115
    new-instance v1, Ljava/io/File;

    const-string v3, "/system/app/Superuser.apk"

    invoke-direct {v1, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 116
    .local v1, "rootFile":Ljava/io/File;
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    move-result v3

    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    .line 117
    .local v0, "doesexist":Ljava/lang/Boolean;
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-ne v3, v2, :cond_0

    .line 123
    :goto_0
    return v2

    :cond_0
    const/4 v2, 0x0

    goto :goto_0
.end method


# virtual methods
.method public callPreferences()V
    .locals 2

    .prologue
    .line 176
    new-instance v0, Landroid/content/Intent;

    const-class v1, Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 177
    .local v0, "i":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/PostLogin;->startActivity(Landroid/content/Intent;)V

    .line 178
    return-void
.end method

.method protected changePasswd()V
    .locals 3

    .prologue
    .line 132
    new-instance v0, Landroid/content/Intent;

    invoke-virtual {p0}, Lcom/android/insecurebankv2/PostLogin;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-class v2, Lcom/android/insecurebankv2/ChangePassword;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 133
    .local v0, "cP":Landroid/content/Intent;
    const-string v1, "uname"

    iget-object v2, p0, Lcom/android/insecurebankv2/PostLogin;->uname:Ljava/lang/String;

    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 134
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/PostLogin;->startActivity(Landroid/content/Intent;)V

    .line 135
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    .line 41
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 42
    const v1, 0x7f04001e

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/PostLogin;->setContentView(I)V

    .line 43
    invoke-virtual {p0}, Lcom/android/insecurebankv2/PostLogin;->getIntent()Landroid/content/Intent;

    move-result-object v0

    .line 44
    .local v0, "intent":Landroid/content/Intent;
    const-string v1, "uname"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->uname:Ljava/lang/String;

    .line 46
    const v1, 0x7f0d0080

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/PostLogin;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/TextView;

    iput-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->root_status:Landroid/widget/TextView;

    .line 48
    invoke-virtual {p0}, Lcom/android/insecurebankv2/PostLogin;->showRootStatus()V

    .line 52
    const v1, 0x7f0d007d

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/PostLogin;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/Button;

    iput-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->transfer_button:Landroid/widget/Button;

    .line 53
    iget-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->transfer_button:Landroid/widget/Button;

    new-instance v2, Lcom/android/insecurebankv2/PostLogin$1;

    invoke-direct {v2, p0}, Lcom/android/insecurebankv2/PostLogin$1;-><init>(Lcom/android/insecurebankv2/PostLogin;)V

    invoke-virtual {v1, v2}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 65
    const v1, 0x7f0d007e

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/PostLogin;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/Button;

    iput-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->statement_button:Landroid/widget/Button;

    .line 66
    iget-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->statement_button:Landroid/widget/Button;

    new-instance v2, Lcom/android/insecurebankv2/PostLogin$2;

    invoke-direct {v2, p0}, Lcom/android/insecurebankv2/PostLogin$2;-><init>(Lcom/android/insecurebankv2/PostLogin;)V

    invoke-virtual {v1, v2}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 74
    const v1, 0x7f0d007f

    invoke-virtual {p0, v1}, Lcom/android/insecurebankv2/PostLogin;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/Button;

    iput-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->changepasswd_button:Landroid/widget/Button;

    .line 75
    iget-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->changepasswd_button:Landroid/widget/Button;

    new-instance v2, Lcom/android/insecurebankv2/PostLogin$3;

    invoke-direct {v2, p0}, Lcom/android/insecurebankv2/PostLogin$3;-><init>(Lcom/android/insecurebankv2/PostLogin;)V

    invoke-virtual {v1, v2}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 83
    return-void
.end method

.method public onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2
    .param p1, "menu"    # Landroid/view/Menu;

    .prologue
    .line 151
    invoke-virtual {p0}, Lcom/android/insecurebankv2/PostLogin;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    const v1, 0x7f0e0002

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    .line 152
    const/4 v0, 0x1

    return v0
.end method

.method public onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 5
    .param p1, "item"    # Landroid/view/MenuItem;

    .prologue
    const/4 v2, 0x1

    .line 161
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    .line 162
    .local v1, "id":I
    const v3, 0x7f0d009d

    if-ne v1, v3, :cond_0

    .line 163
    invoke-virtual {p0}, Lcom/android/insecurebankv2/PostLogin;->callPreferences()V

    .line 171
    :goto_0
    return v2

    .line 165
    :cond_0
    const v3, 0x7f0d009e

    if-ne v1, v3, :cond_1

    .line 166
    new-instance v0, Landroid/content/Intent;

    invoke-virtual {p0}, Lcom/android/insecurebankv2/PostLogin;->getBaseContext()Landroid/content/Context;

    move-result-object v3

    const-class v4, Lcom/android/insecurebankv2/LoginActivity;

    invoke-direct {v0, v3, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 167
    .local v0, "i":Landroid/content/Intent;
    const/high16 v3, 0x4000000

    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 168
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/PostLogin;->startActivity(Landroid/content/Intent;)V

    goto :goto_0

    .line 171
    .end local v0    # "i":Landroid/content/Intent;
    :cond_1
    invoke-super {p0, p1}, Landroid/app/Activity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result v2

    goto :goto_0
.end method

.method showRootStatus()V
    .locals 3

    .prologue
    const/4 v1, 0x1

    .line 86
    const-string v2, "/system/app/Superuser.apk"

    invoke-direct {p0, v2}, Lcom/android/insecurebankv2/PostLogin;->doesSuperuserApkExist(Ljava/lang/String;)Z

    move-result v2

    if-nez v2, :cond_0

    .line 87
    invoke-direct {p0}, Lcom/android/insecurebankv2/PostLogin;->doesSUexist()Z

    move-result v2

    if-eqz v2, :cond_1

    :cond_0
    move v0, v1

    .line 88
    .local v0, "isrooted":Z
    :goto_0
    if-ne v0, v1, :cond_2

    .line 90
    iget-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->root_status:Landroid/widget/TextView;

    const-string v2, "Rooted Device!!"

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 96
    :goto_1
    return-void

    .line 87
    .end local v0    # "isrooted":Z
    :cond_1
    const/4 v0, 0x0

    goto :goto_0

    .line 94
    .restart local v0    # "isrooted":Z
    :cond_2
    iget-object v1, p0, Lcom/android/insecurebankv2/PostLogin;->root_status:Landroid/widget/TextView;

    const-string v2, "Device not Rooted!!"

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    goto :goto_1
.end method

.method protected viewStatment()V
    .locals 3

    .prologue
    .line 142
    new-instance v0, Landroid/content/Intent;

    invoke-virtual {p0}, Lcom/android/insecurebankv2/PostLogin;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-class v2, Lcom/android/insecurebankv2/ViewStatement;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 143
    .local v0, "vS":Landroid/content/Intent;
    const-string v1, "uname"

    iget-object v2, p0, Lcom/android/insecurebankv2/PostLogin;->uname:Ljava/lang/String;

    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 144
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/PostLogin;->startActivity(Landroid/content/Intent;)V

    .line 145
    return-void
.end method
