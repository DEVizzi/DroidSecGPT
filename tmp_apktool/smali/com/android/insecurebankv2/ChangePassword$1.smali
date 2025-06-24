.class Lcom/android/insecurebankv2/ChangePassword$1;
.super Ljava/lang/Object;
.source "ChangePassword.java"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/ChangePassword;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/android/insecurebankv2/ChangePassword;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/ChangePassword;)V
    .locals 0
    .param p1, "this$0"    # Lcom/android/insecurebankv2/ChangePassword;

    .prologue
    .line 92
    iput-object p1, p0, Lcom/android/insecurebankv2/ChangePassword$1;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 4
    .param p1, "v"    # Landroid/view/View;

    .prologue
    .line 97
    new-instance v0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v1, p0, Lcom/android/insecurebankv2/ChangePassword$1;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    invoke-direct {v0, v1}, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;-><init>(Lcom/android/insecurebankv2/ChangePassword;)V

    const/4 v1, 0x1

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x0

    iget-object v3, p0, Lcom/android/insecurebankv2/ChangePassword$1;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    iget-object v3, v3, Lcom/android/insecurebankv2/ChangePassword;->uname:Ljava/lang/String;

    aput-object v3, v1, v2

    invoke-virtual {v0, v1}, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;

    .line 98
    return-void
.end method
