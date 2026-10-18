from cryptography.exceptions import InvalidTag
import crypto_core as cc
import shamir 

testamento = b"Testamento de Juan Perez: lego mi casa a mi hija Maria."
id_doc = b"DOC-2026-0001"

print("=== 1. Hash y firma ===")
privada, publica = cc.generar_par_firma()
firma = cc.firmar(privada, testamento)
print(f"SHA-256:        {cc.huella(testamento).hex()[:32]}...")
print(f"Firma Ed25519:  {firma.hex()[:32]}...")

print("\n=== 2. Cifrado, División de Llave (Shamir) y Descifrado (AES-256-GCM) ===")
# 2.1 Generar llave original
llave_original = cc.generar_llave()

# 2.2 Dividir la llave con el esquema de Shamir (2 de 2)
print("-> Dividiendo llave con Shamir (t=2, n=2)...")
fragmentos = shamir.dividir_secreto(llave_original, t=2, n=2)

# 2.3 Cifrar el documento con la llave original
paquete = cc.cifrar(llave_original, testamento, id_doc)
print(f"Cifrado:        {paquete.hex()[:32]}... ({len(paquete)} bytes)")

# 2.4 Simular que los actores entregan sus fragmentos y se reconstruye la llave
print("-> Reconstruyendo llave a partir de fragmentos...")
llave_reconstruida = shamir.reconstruir_secreto(fragmentos)

# 2.5 Descifrar el documento usando la llave reconstruida
print("Descifrado:    ", cc.descifrar(llave_reconstruida, paquete, id_doc).decode())

print("\n=== 3. Descifrar con una llave incorrecta ===")
try:
    cc.descifrar(cc.generar_llave(), paquete, id_doc)
    print("ERROR: no debió descifrarse")
except InvalidTag:
    print("Rechazado: llave incorrecta (InvalidTag)")

print("\n=== 4. Alterar un byte del documento cifrado ===")
alterado = bytearray(paquete)
alterado[20] ^= 0x01
try:
    cc.descifrar(llave_original, bytes(alterado), id_doc)
    print("ERROR: no debió descifrarse")
except InvalidTag:
    print("Rechazado: GCM detectó la modificación (InvalidTag)")

print("\n=== 5. Verificar firma sobre un documento falsificado ===")
falso = b"Testamento de Juan Perez: lego mi casa a mi vecino Pedro."
print("Firma valida (original):   ", cc.verificar_firma(publica, testamento, firma))
print("Firma valida (falsificado):", cc.verificar_firma(publica, falso, firma))