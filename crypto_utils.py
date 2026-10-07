import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def generate_rsa_keys():
    # إنشاء مفتاح RSA خاص بحجم 2048 بت
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # استخراج المفتاح العام من المفتاح الخاص
    public_key = private_key.public_key()

    # إرجاع المفتاح الخاص والمفتاح العام
    return private_key, public_key


def save_private_key(private_key, filename):
    try:
        # تحويل المفتاح الخاص إلى صيغة PEM
        data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # فتح الملف للكتابة بصيغة ثنائية
        file = open(filename, "wb")

        # حفظ المفتاح في الملف
        file.write(data)

        # إغلاق الملف
        file.close()
    except Exception as error:
        # طباعة رسالة عند حدوث خطأ
        print("Error while saving private key:", error)


def save_public_key(public_key, filename):
    try:
        # تحويل المفتاح العام إلى صيغة PEM
        data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # فتح الملف للكتابة بصيغة ثنائية
        file = open(filename, "wb")

        # حفظ المفتاح في الملف
        file.write(data)

        # إغلاق الملف
        file.close()
    except Exception as error:
        # طباعة رسالة عند حدوث خطأ
        print("Error while saving public key:", error)


def load_private_key(filename):
    try:
        # فتح ملف المفتاح الخاص للقراءة
        file = open(filename, "rb")

        # قراءة بيانات المفتاح
        data = file.read()

        # إغلاق الملف
        file.close()

        # تحويل بيانات PEM إلى مفتاح خاص
        private_key = serialization.load_pem_private_key(
            data,
            password=None
        )

        # إرجاع المفتاح الخاص
        return private_key
    except Exception as error:
        # طباعة رسالة عند حدوث خطأ
        print("Error while loading private key:", error)
        return None


def load_public_key(filename):
    try:
        # فتح ملف المفتاح العام للقراءة
        file = open(filename, "rb")

        # قراءة بيانات المفتاح
        data = file.read()

        # إغلاق الملف
        file.close()

        # تحويل بيانات PEM إلى مفتاح عام
        public_key = serialization.load_pem_public_key(data)

        # إرجاع المفتاح العام
        return public_key
    except Exception as error:
        # طباعة رسالة عند حدوث خطأ
        print("Error while loading public key:", error)
        return None


def public_key_to_bytes(public_key):
    # تحويل المفتاح العام إلى بيانات يمكن إرسالها عبر الشبكة
    data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # إرجاع البيانات
    return data


def bytes_to_public_key(data):
    try:
        # تحويل البيانات القادمة من الشبكة إلى مفتاح عام
        public_key = serialization.load_pem_public_key(data)

        # إرجاع المفتاح العام
        return public_key
    except Exception as error:
        # طباعة رسالة عند حدوث خطأ
        print("Error while converting data to public key:", error)
        return None


def rsa_encrypt_session_key(public_key, session_key):
    # تشفير مفتاح الجلسة باستخدام RSA-OAEP و SHA-256
    ciphertext = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # إرجاع النص المشفر
    return ciphertext


def rsa_decrypt_session_key(private_key, ciphertext):
    # فك تشفير مفتاح الجلسة باستخدام RSA-OAEP و SHA-256
    session_key = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # إرجاع مفتاح الجلسة
    return session_key


def derive_chacha_key(session_key):
    # إنشاء HKDF باستخدام SHA-256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chacha20-key"
    )

    # اشتقاق مفتاح حجمه 32 بايت
    key = hkdf.derive(session_key)

    # إرجاع المفتاح الجديد
    return key


def generate_session_key():
    # إنشاء مفتاح جلسة عشوائي حجمه 32 بايت
    session_key = os.urandom(32)

    # إرجاع مفتاح الجلسة
    return session_key


def chacha_encrypt(key, plaintext):
    # إنشاء رقم عشوائي يستخدم مرة واحدة وحجمه 12 بايت
    nonce = os.urandom(12)

    # إنشاء كائن التشفير ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(key)

    # تشفير النص وإضافة رمز التحقق
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    # إرجاع الرقم العشوائي والنص المشفر
    return nonce, ciphertext


def chacha_decrypt(key, nonce, ciphertext):
    # إنشاء كائن فك التشفير ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(key)

    # فك تشفير النص والتحقق منه
    plaintext = cipher.decrypt(nonce, ciphertext, None)

    # إرجاع النص الأصلي
    return plaintext


def sha256_hash(data):
    # حساب قيمة SHA-256 للبيانات
    result = hashlib.sha256(data).hexdigest()

    # إرجاع القيمة بصيغة نصية hex
    return result


if __name__ == "__main__":
    try:
        # إنشاء مفاتيح RSA
        private_key, public_key = generate_rsa_keys()

        # إنشاء مفتاح جلسة
        session_key = generate_session_key()

        # تشفير مفتاح الجلسة وفك تشفيره
        encrypted_session_key = rsa_encrypt_session_key(
            public_key,
            session_key
        )
        decrypted_session_key = rsa_decrypt_session_key(
            private_key,
            encrypted_session_key
        )

        # اشتقاق مفتاح ChaCha20
        chacha_key = derive_chacha_key(decrypted_session_key)

        # تشفير رسالة تجريبية
        message = "Hello Ali".encode("utf-8")
        nonce, encrypted_message = chacha_encrypt(chacha_key, message)

        # فك تشفير الرسالة
        decrypted_message = chacha_decrypt(
            chacha_key,
            nonce,
            encrypted_message
        )

        # اختبار تحويل المفتاح العام إلى bytes ثم إعادته
        public_key_data = public_key_to_bytes(public_key)
        new_public_key = bytes_to_public_key(public_key_data)

        # طباعة نتائج الاختبار بالعربية
        print("RSA keys were created successfully")
        print("Session key encryption and decryption:", session_key == decrypted_session_key)
        print("Message after decryption:", decrypted_message.decode("utf-8"))
        print("Public key conversion was successful:", new_public_key is not None)
        print("SHA-256 value:", sha256_hash(message))
    except Exception as error:
        # طباعة رسالة عند حدوث خطأ في الاختبار
        print("Error in test:", error)
