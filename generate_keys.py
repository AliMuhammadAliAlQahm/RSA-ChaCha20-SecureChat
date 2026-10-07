# استيراد الدوال الخاصة بإنشاء وحفظ المفاتيح
from crypto_utils import generate_rsa_keys, save_private_key, save_public_key

# استيراد مكتبة التعامل مع المجلدات
import os


# إنشاء مجلد المفاتيح إذا لم يكن موجودا
os.makedirs("keys", exist_ok=True)


# إنشاء وحفظ مفاتيح الخادم
print("Generating server keys...")
server_private, server_public = generate_rsa_keys()
save_private_key(server_private, "keys/server_private.pem")
save_public_key(server_public, "keys/server_public.pem")
print("Server keys saved.")


# إنشاء وحفظ مفاتيح العميل A
print("Generating client A keys...")
clientA_private, clientA_public = generate_rsa_keys()
save_private_key(clientA_private, "keys/clientA_private.pem")
save_public_key(clientA_public, "keys/clientA_public.pem")
print("Client A keys saved.")


# إنشاء وحفظ مفاتيح العميل B
print("Generating client B keys...")
clientB_private, clientB_public = generate_rsa_keys()
save_private_key(clientB_private, "keys/clientB_private.pem")
save_public_key(clientB_public, "keys/clientB_public.pem")
print("Client B keys saved.")


# طباعة رسالة نجاح بعد إنشاء كل المفاتيح
print("All keys generated successfully!")
