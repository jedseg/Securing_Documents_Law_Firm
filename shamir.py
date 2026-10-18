"""
Esquema de compartición de secretos de Shamir (t de n), implementación propia.

Idea: el secreto S es el término independiente de un polinomio aleatorio
f(x) = S + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}  (mod p).
Cada fragmento es un punto (x_i, f(x_i)). Con t puntos se reconstruye f(0) = S
por interpolación de Lagrange; con t-1 puntos no se obtiene información de S.

Se trabaja en el campo finito Z_p con p = 2^521 - 1 (primo de Mersenne),
que es mayor que cualquier llave de 256 bits.
"""

import secrets

P = 2**521 - 1


def _evaluar_polinomio(coeficientes: list[int], x: int) -> int:
    """Evalúa el polinomio en x (mod p) con el método de Horner."""
    resultado = 0
    for coef in reversed(coeficientes):
        resultado = (resultado * x + coef) % P
    return resultado


def dividir_secreto(secreto: bytes, t: int, n: int) -> list[tuple[int, int]]:
    """Divide `secreto` en n fragmentos; se necesitan t para reconstruirlo."""
    if not 2 <= t <= n:
        raise ValueError("Se requiere 2 <= t <= n")
    s = int.from_bytes(secreto, "big")
    if s >= P:
        raise ValueError("El secreto es demasiado grande para el campo")

    # f(0) = secreto; los demás coeficientes son aleatorios (CSPRNG)
    coeficientes = [s] + [secrets.randbelow(P) for _ in range(t - 1)]
    return [(x, _evaluar_polinomio(coeficientes, x)) for x in range(1, n + 1)]


def reconstruir_secreto(fragmentos: list[tuple[int, int]], longitud: int = 32) -> bytes:
    """Reconstruye f(0) con interpolación de Lagrange a partir de los fragmentos."""
    xs = [x for x, _ in fragmentos]
    if len(set(xs)) != len(xs):
        raise ValueError("Fragmentos repetidos")

    secreto = 0
    for i, (xi, yi) in enumerate(fragmentos):
        numerador, denominador = 1, 1
        for j, (xj, _) in enumerate(fragmentos):
            if i != j:
                numerador = (numerador * (-xj)) % P
                denominador = (denominador * (xi - xj)) % P
        # División modular: multiplicar por el inverso de denominador mod p
        termino = yi * numerador * pow(denominador, -1, P)
        secreto = (secreto + termino) % P

    # Con menos de t fragmentos el valor resultante es basura y puede no caber
    # en `longitud` bytes; se reduce para que el error aparezca al descifrar.
    secreto %= 2 ** (8 * longitud)
    return secreto.to_bytes(longitud, "big")
