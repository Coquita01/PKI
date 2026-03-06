# Importamos:
# hashes: algoritmos hash criptográficos como SHA-256
# serialization: (ya no se usa para llaves asimétricas en modo PQ, pero lo dejo por tu estructura)
from cryptography.hazmat.primitives import hashes, serialization

# Importamos herramientas de criptografía simétrica
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Backend criptográfico (OpenSSL)
from cryptography.hazmat.backends import default_backend

# Aleatoriedad
import secrets
import base64

# postcuantico (Open Quantum Safe)
import oqs

# Derivación de clave simétrica desde el secreto compartido (KEM)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ML-KEM (Kyber) para intercambio de clave
KEM_ALG = "ML-KEM-768"

# ML-DSA (Dilithium)
SIG_ALG = "ML-DSA-65"


class ParClaves:
    def __init__(self) -> None:

        self.__sig = oqs.Signature(SIG_ALG)
        pub = self.__sig.generate_keypair()  # bytes (public key)
        try:
            sec = self.__sig.export_secret_key()  # bytes (secret key)
        except Exception:
            sec = None

        self.__clave_publica = base64.b64encode(pub).decode("utf-8")
        self.__clave_privada = base64.b64encode(sec).decode("utf-8")

    @property
    def clave_privada(self):
        return self.__clave_privada

    @property
    def clave_publica(self):
        return self.__clave_publica


class MensajeCifrado:
    def __init__(self, contenido, firma):
        if contenido is None:
            raise TypeError("contenido no puede ser None")
        if firma is None:
            raise TypeError("firma no puede ser None")
        if not isinstance(contenido, str):
            raise TypeError("contenido debe ser str.")
        if not isinstance(firma, str):
            raise TypeError("firma debe ser str.")
        self.contenido = contenido
        self.firma = firma


class SesionCifrada:
    def __init__(self):
        # Par de claves para firma (ML-DSA)
        self.__par_claves = ParClaves()

        # __clave_remota: CLAVE PÚBLICA KEM remota (ML-KEM) en bytes
        # __clave_remota_sig: clave pública de firma remota (ML-DSA) en bytes
        self.__clave_remota = None
        self.__clave_remota_sig = None

        # KEM propio (ML-KEM)
        self.__kem = oqs.KeyEncapsulation(KEM_ALG)
        self.__kem_public_key = self.__kem.generate_keypair()  # bytes

        self.establecida = False

    #  devuelve la clave pública de firma (ML-DSA) en Base64
    def obtener_clave_publica(self):
        return self.__par_claves.clave_publica

    # clave pública KEM (ML-KEM) en Base64
    def obtener_clave_publica_kem(self):
        return base64.b64encode(self.__kem_public_key).decode("utf-8")

    def reiniciar_sesion(self):
        self.__clave_remota = None
        self.__clave_remota_sig = None
        self.establecida = False

    def establecer_clave_remota(self, clave_remota):

        if clave_remota is None:
            raise ValueError("contenido no puede ser None")
        if not isinstance(clave_remota, str):
            raise TypeError("contenido debe ser string")
        if clave_remota == "":
            raise ValueError("contenido no puede estar vacio")

        delim = "\n-----DELIM-----\n"
        if delim not in clave_remota:
            raise ValueError(
                "Formato inválido. Debes enviar: KEM_B64 + '\\n-----DELIM-----\\n' + SIG_B64"
            )

        kem_b64, sig_b64 = clave_remota.split(delim, 1)

        self.__clave_remota = base64.b64decode(kem_b64.strip(), validate=True)
        self.__clave_remota_sig = base64.b64decode(sig_b64.strip(), validate=True)

        self.establecida = True

    def establecida(self):
        return self.establecida

    def _derivar_clave_aes_desde_ss(self, shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,          # AES-256
            salt=None,
            info=b"SesionCifrada AES-256 key v1",
        ).derive(shared_secret)

    def cifrar(self, mensaje: str):
        if not self.establecida:
            raise RuntimeError("sesion no está establecida.")
        if mensaje is None:
            raise TypeError("mensaje no puede ser None.")
        if not isinstance(mensaje, str):
            raise TypeError("mensaje debe ser str.")

        # ML-KEM encaps con la pub KEM remota
        with oqs.KeyEncapsulation(KEM_ALG) as kem_sender:
            ct_kem, shared_secret = kem_sender.encap_secret(self.__clave_remota)

        # Derivar AES-256 desde shared_secret
        clave_simetrica = self._derivar_clave_aes_desde_ss(shared_secret)

        #  AES-CBC + PKCS7
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(clave_simetrica), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        mensaje_bytes = mensaje.encode("utf-8")
        padding_len = 16 - (len(mensaje_bytes) % 16)
        mensaje_padded = mensaje_bytes + bytes([padding_len] * padding_len)

        mensaje_cifrado = encryptor.update(mensaje_padded) + encryptor.finalize()

        paquete = ct_kem + iv + mensaje_cifrado
        paquete_b64 = base64.b64encode(paquete).decode("utf-8")

        paquete_bytes = paquete  # lo firmamos como bytes
        sig = oqs.Signature(SIG_ALG)

        # Importamos secret key
        if self.__par_claves.clave_privada is None:
            raise RuntimeError("Tu versión de oqs no permite exportar secret key; no puedo firmar fuera del objeto original.")
        sk = base64.b64decode(self.__par_claves.clave_privada.encode("utf-8"), validate=True)
        try:
            sig.import_secret_key(sk)
        except Exception:
            raise RuntimeError("Tu binding oqs no soporta import_secret_key; ajusta a un flujo donde mantengas el objeto signer vivo.")

        firma = sig.sign(paquete_bytes)
        firma_b64 = base64.b64encode(firma).decode("utf-8")

        return MensajeCifrado(paquete_b64, firma_b64)

    def verificar_firma(self, mensaje_cifrado: MensajeCifrado):
        if not self.establecida:
            raise RuntimeError("La sesión no está establecida. No se puede verificar la firma.")
        if mensaje_cifrado is None:
            raise TypeError("mensaje_cifrado no puede ser None")
        if not isinstance(mensaje_cifrado, MensajeCifrado):
            raise TypeError("mensaje_cifrado debe ser de tipo MensajeCifrado")

        try:
            paquete_recibido = base64.b64decode(mensaje_cifrado.contenido, validate=True)
            firma_recibida = base64.b64decode(mensaje_cifrado.firma, validate=True)

            # Verificación ML-DSA
            verifier = oqs.Signature(SIG_ALG)
            ok = verifier.verify(paquete_recibido, firma_recibida, self.__clave_remota_sig)
            return bool(ok)
        except Exception:
            return False

    def descifrar(self, mensaje_cifrado: MensajeCifrado):
        if not self.establecida:
            raise RuntimeError("La sesión no está establecida. No se puede descifrar el mensaje.")
        if mensaje_cifrado is None:
            raise TypeError("mensaje_cifrado no puede ser None")
        if not isinstance(mensaje_cifrado, MensajeCifrado):
            raise TypeError("mensaje_cifrado debe ser de tipo MensajeCifrado")

        if not self.verificar_firma(mensaje_cifrado):
            raise ValueError("La firma del mensaje no es válida")

        paquete_recibido = base64.b64decode(mensaje_cifrado.contenido, validate=True)

        # Tamaño del ciphertext KEM
        try:
            tam_clave = self.__kem.details["length_ciphertext"]
        except Exception:
            raise ValueError("No se pudo obtener el tamaño del ciphertext KEM.")

        if len(paquete_recibido) < tam_clave + 16:
            raise ValueError("Paquete inválido o incompleto.")

        ct_kem = paquete_recibido[:tam_clave]
        iv_recuperado = paquete_recibido[tam_clave:tam_clave + 16]
        mensaje_cifrado_recuperado = paquete_recibido[tam_clave + 16:]

        try:
            shared_secret = self.__kem.decap_secret(ct_kem)
            clave_simetrica = self._derivar_clave_aes_desde_ss(shared_secret)
        except Exception:
            raise ValueError("No se pudo recuperar la clave simétrica mediante ML-KEM.")

        cipher = Cipher(
            algorithms.AES(clave_simetrica),
            modes.CBC(iv_recuperado),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        mensaje_padded = decryptor.update(mensaje_cifrado_recuperado) + decryptor.finalize()

        mensaje_final = mensaje_padded[:-mensaje_padded[-1]].decode("utf-8")
        return mensaje_final