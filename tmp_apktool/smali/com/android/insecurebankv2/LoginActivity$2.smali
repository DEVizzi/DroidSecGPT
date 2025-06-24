.class Lcom/android/insecurebankv2/LoginActivity$2;
.super Ljava/lang/Object;
.source "LoginActivity.java"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/LoginActivity;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/android/insecurebankv2/LoginActivity;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/LoginActivity;)V
    .locals 0
    .param p1, "this$0"    # Lcom/android/insecurebankv2/LoginActivity;

    .prologue
    .line 66
    iput-object p1, p0, Lcom/android/insecurebankv2/LoginActivity$2;->this$0:Lcom/android/insecurebankv2/LoginActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 1
    .param p1, "v"    # Landroid/view/View;

    .prologue
    .line 71
    iget-object v0, p0, Lcom/android/insecurebankv2/LoginActivity$2;->this$0:Lcom/android/insecurebankv2/LoginActivity;

    invoke-virtual {v0}, Lcom/android/insecurebankv2/LoginActivity;->createUser()V

    .line 72
    return-void
.end method
