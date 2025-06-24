.class Lcom/android/insecurebankv2/PostLogin$1;
.super Ljava/lang/Object;
.source "PostLogin.java"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/PostLogin;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/android/insecurebankv2/PostLogin;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/PostLogin;)V
    .locals 0
    .param p1, "this$0"    # Lcom/android/insecurebankv2/PostLogin;

    .prologue
    .line 53
    iput-object p1, p0, Lcom/android/insecurebankv2/PostLogin$1;->this$0:Lcom/android/insecurebankv2/PostLogin;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 3
    .param p1, "v"    # Landroid/view/View;

    .prologue
    .line 61
    new-instance v0, Landroid/content/Intent;

    iget-object v1, p0, Lcom/android/insecurebankv2/PostLogin$1;->this$0:Lcom/android/insecurebankv2/PostLogin;

    invoke-virtual {v1}, Lcom/android/insecurebankv2/PostLogin;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-class v2, Lcom/android/insecurebankv2/DoTransfer;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 62
    .local v0, "dT":Landroid/content/Intent;
    iget-object v1, p0, Lcom/android/insecurebankv2/PostLogin$1;->this$0:Lcom/android/insecurebankv2/PostLogin;

    invoke-virtual {v1, v0}, Lcom/android/insecurebankv2/PostLogin;->startActivity(Landroid/content/Intent;)V

    .line 63
    return-void
.end method
